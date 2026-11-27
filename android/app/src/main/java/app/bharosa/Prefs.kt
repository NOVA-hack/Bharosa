package app.bharosa

import android.content.Context
import org.json.JSONObject

/**
 * What the app remembers on the phone: the relay address, this member's token and role, the
 * language, and the raw upi:// links of payments waiting for a guardian.
 *
 * The raw link stays on this phone only; the relay keeps just the masked case. Prototype note:
 * this is plain SharedPreferences. Move the token to EncryptedSharedPreferences/Keystore before
 * real use.
 */
class Prefs(context: Context) {
    private val sp = context.applicationContext.getSharedPreferences("bharosa", Context.MODE_PRIVATE)

    var relayUrl: String
        get() = sp.getString("relay_url", null) ?: BuildConfig.DEFAULT_RELAY
        set(v) = sp.edit().putString("relay_url", v.trim().trimEnd('/')).apply()

    var lang: String
        get() = sp.getString("lang", "en") ?: "en"
        set(v) = sp.edit().putString("lang", v).apply()

    val token: String? get() = sp.getString("token", null)
    val role: String? get() = sp.getString("role", null)
    val name: String? get() = sp.getString("name", null)
    val isParent get() = role == "parent" && token != null
    val isGuardian get() = role == "guardian" && token != null

    fun saveMembership(m: Membership) {
        sp.edit().putString("token", m.token).putString("role", m.role).putString("name", m.name)
            .putString("family_id", m.familyId).putString("user_id", m.userId).apply()
    }

    fun forget() {
        sp.edit().remove("token").remove("role").remove("name").remove("family_id").remove("user_id")
            .remove("pending").apply()
    }

    fun api(): BharosaApi = BharosaApi(relayUrl, token)

    // ---- payments waiting for a guardian (case id -> raw upi:// link) --------------------

    fun rememberPending(caseId: String, upiLink: String) {
        val o = pendingJson().put(caseId, upiLink)
        sp.edit().putString("pending", o.toString()).apply()
    }

    fun pendingLink(caseId: String): String? = pendingJson().optStringOrNull(caseId)

    fun pendingIds(): List<String> = pendingJson().keys().asSequence().toList()

    fun dropPending(caseId: String) {
        val o = pendingJson()
        o.remove(caseId)
        sp.edit().putString("pending", o.toString()).apply()
    }

    private fun pendingJson(): JSONObject = try {
        JSONObject(sp.getString("pending", "{}") ?: "{}")
    } catch (_: Exception) {
        JSONObject()
    }
}
