package app.bharosa

import org.json.JSONArray
import org.json.JSONObject

/** What the relay found. Every field comes from the relay's deterministic checks. */
data class Reason(val ruleId: String, val severity: String, val text: String, val evidence: String?)

data class TruthCard(val text: String, val source: String, val url: String)

data class CheckResult(
    val caseId: String,
    val inputType: String,
    val riskLevel: String,
    val score: Int,
    val headline: String,
    val reasons: List<Reason>,
    val truthCards: List<TruthCard>,
    val disclaimer: String,
    val maskSummary: String,
    val payeeMasked: String?,
    val amount: Double?,
    val isPayment: Boolean,
    val inputSha256: String,
    val state: String,
    /** proceed | hold | stop | warn */
    val action: String,
    val message: String?,
    val codeWordPrompt: String?,
    val queueError: String?,
    val guardiansNotified: Int?,
    val rulesetVersion: String,
) {
    companion object {
        fun parse(o: JSONObject) = CheckResult(
            caseId = o.getString("case_id"),
            inputType = o.optString("input_type", "msg"),
            riskLevel = o.getString("risk_level"),
            score = o.optInt("score", 0),
            headline = o.optString("headline"),
            reasons = parseReasons(o.optJSONArray("reasons")),
            truthCards = o.optJSONArray("truth_cards").objects().map {
                TruthCard(it.optString("text"), it.optString("source"), it.optString("url"))
            },
            disclaimer = o.optString("disclaimer"),
            maskSummary = o.optString("mask_summary"),
            payeeMasked = o.optStringOrNull("payee_masked"),
            amount = o.optDoubleOrNull("amount"),
            isPayment = o.optBoolean("is_payment", false),
            inputSha256 = o.optString("input_sha256"),
            state = o.optString("state"),
            action = o.optString("action", "warn"),
            message = o.optStringOrNull("message"),
            codeWordPrompt = o.optStringOrNull("code_word_prompt"),
            queueError = o.optStringOrNull("queue_error"),
            guardiansNotified = if (o.has("guardians_notified") && !o.isNull("guardians_notified"))
                o.getInt("guardians_notified") else null,
            rulesetVersion = o.optString("ruleset_version"),
        )
    }
}

/** A case as the family queue stores it (masked content only). */
data class FamilyCase(
    val id: String,
    val inputType: String,
    val maskedContent: String,
    val riskLevel: String,
    val score: Int,
    val state: String,
    val parentName: String?,
    val payeeMasked: String?,
    val amount: Double?,
    val inputSha256: String?,
    val reasons: List<Reason>,
    val approvalNote: String?,
    val expiresAt: Double?,
) {
    companion object {
        fun parse(o: JSONObject): FamilyCase {
            val approval = o.optJSONObject("approval")
            return FamilyCase(
                id = o.optString("id", o.optString("case_id")),
                inputType = o.optString("input_type", "msg"),
                maskedContent = o.optString("masked_content"),
                riskLevel = o.optString("risk_level", "medium"),
                score = o.optInt("score", 0),
                state = o.optString("state"),
                parentName = o.optStringOrNull("parent_name"),
                payeeMasked = o.optStringOrNull("payee_masked"),
                amount = o.optDoubleOrNull("amount"),
                inputSha256 = o.optStringOrNull("input_sha256"),
                reasons = parseReasons(o.optJSONArray("reasons"), textKey = "title"),
                approvalNote = approval?.optStringOrNull("note"),
                expiresAt = approval?.optDoubleOrNull("expires_at") ?: o.optDoubleOrNull("expires_at"),
            )
        }
    }
}

data class Membership(val token: String, val userId: String, val familyId: String, val role: String,
                      val name: String, val pairCode: String?)

internal fun parseReasons(a: JSONArray?, textKey: String = "text"): List<Reason> =
    a.objects().map {
        Reason(
            ruleId = it.optString("rule_id"),
            severity = it.optString("severity"),
            text = it.optString(textKey).ifEmpty { it.optString("title", it.optString("rule_id")) },
            evidence = it.optStringOrNull("evidence"),
        )
    }

internal fun JSONArray?.objects(): List<JSONObject> {
    if (this == null) return emptyList()
    return (0 until length()).mapNotNull { optJSONObject(it) }
}

internal fun JSONObject.optStringOrNull(key: String): String? =
    if (!has(key) || isNull(key)) null else optString(key).ifEmpty { null }

internal fun JSONObject.optDoubleOrNull(key: String): Double? =
    if (!has(key) || isNull(key)) null else optDouble(key).takeIf { !it.isNaN() }
