package app.bharosa

import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

class ApiError(val status: Int, val code: String, message: String) : IOException(message)

/**
 * Blocking client for the Bharosa family relay (`bharosa relay`). Call it off the main thread.
 * Uses only HttpURLConnection and org.json, which ship with Android.
 */
class BharosaApi(baseUrl: String, private val token: String? = null) {
    private val base = baseUrl.trim().trimEnd('/')

    fun health(): JSONObject = call("GET", "/health")

    // ---- pairing ---------------------------------------------------------------------

    fun createFamily(parentName: String, lang: String): Membership {
        val o = call("POST", "/families", JSONObject().put("parent_name", parentName).put("language", lang))
        return Membership(o.getString("token"), o.getString("user_id"), o.getString("family_id"), "parent",
            parentName, o.optStringOrNull("pair_code"))
    }

    fun joinFamily(pairCode: String, guardianName: String, lang: String): Membership {
        val o = call("POST", "/join", JSONObject().put("pair_code", pairCode.trim())
            .put("guardian_name", guardianName).put("language", lang))
        return Membership(o.getString("token"), o.getString("user_id"), o.getString("family_id"), "guardian",
            guardianName, null)
    }

    fun newPairCode(): String = call("POST", "/pair-codes").getString("pair_code")

    fun me(): JSONObject = call("GET", "/me")

    fun family(): JSONObject = call("GET", "/family")

    // ---- checks and the family queue -------------------------------------------------

    /** Ask the relay for a verdict. For a paired parent, a risky case is held for a guardian. */
    fun check(content: String, kind: String, lang: String): CheckResult =
        CheckResult.parse(call("POST", "/check",
            JSONObject().put("content", content).put("kind", kind).put("lang", lang)))

    fun case(caseId: String): FamilyCase = FamilyCase.parse(call("GET", "/cases/${enc(caseId)}"))

    fun caseState(caseId: String): String = call("GET", "/cases/${enc(caseId)}/status").getString("state")

    fun heldCases(): List<FamilyCase> = callArray("GET", "/cases?state=held").objects().map { FamilyCase.parse(it) }

    fun recentCases(limit: Int = 20): List<FamilyCase> =
        callArray("GET", "/cases?limit=$limit").objects().map { FamilyCase.parse(it) }

    fun decide(caseId: String, approve: Boolean, note: String?): FamilyCase {
        val body = JSONObject().put("decision", if (approve) "approve" else "block")
        if (!note.isNullOrBlank()) body.put("note", note.trim().take(280))
        return FamilyCase.parse(call("POST", "/cases/${enc(caseId)}/decision", body))
    }

    /** Tell the family queue the parent is continuing to a UPI app. Refused unless allowed or approved. */
    fun handoff(caseId: String): JSONObject = call("POST", "/cases/${enc(caseId)}/handoff")

    fun emergencyStop(reason: String): JSONObject = call("POST", "/stop", JSONObject().put("reason", reason))

    fun unlock(): JSONObject = call("POST", "/unlock")

    // ---- plumbing --------------------------------------------------------------------

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    private fun call(method: String, path: String, body: JSONObject? = null): JSONObject {
        val text = raw(method, path, body)
        return if (text.isBlank()) JSONObject() else JSONObject(text)
    }

    private fun callArray(method: String, path: String): JSONArray = JSONArray(raw(method, path, null))

    private fun raw(method: String, path: String, body: JSONObject?): String {
        val conn = (URL(base + path).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 8000
            readTimeout = 15000
            setRequestProperty("Accept", "application/json")
            if (token != null) setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
        }
        try {
            if (body != null) conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
            if (status !in 200..299) throw errorFrom(status, text)
            return text
        } finally {
            conn.disconnect()
        }
    }

    companion object {
        /** Turn a relay error body ({"error","detail"} or FastAPI's {"detail"}) into a readable ApiError. */
        fun errorFrom(status: Int, text: String): ApiError {
            var code = "http_$status"
            var detail = text.take(200).ifBlank { "HTTP $status" }
            try {
                val o = JSONObject(text)
                code = o.optString("error", code)
                val d = o.opt("detail")
                detail = when (d) {
                    is String -> d
                    is JSONArray -> d.objects().joinToString("; ") { it.optString("msg") }.ifBlank { detail }
                    else -> detail
                }
            } catch (_: Exception) {
            }
            return ApiError(status, code, detail)
        }
    }
}
