package app.bharosa

import java.net.URLDecoder
import java.security.MessageDigest

/**
 * Small pure helpers for links and shared text. No Android classes here, so they run in plain
 * JVM unit tests. Risk decisions are NOT made here: the relay's deterministic rule packs decide.
 * This file only decides what to send for checking and whether a link is safe to hand to a UPI app
 * at all (a well-formed upi://pay link, nothing else).
 */
object UpiLinks {
    private val UPI_IN_TEXT = Regex("""upi://[^\s<>"']+""", RegexOption.IGNORE_CASE)
    private val URL_ONLY = Regex("""^(https?://|www\.)\S+$""", RegexOption.IGNORE_CASE)
    private val UPI_ONLY = Regex("""^upi://\S+$""", RegexOption.IGNORE_CASE)
    private val VPA = Regex("""^[A-Za-z0-9.\-_]{2,256}@[A-Za-z][A-Za-z0-9.\-]{1,64}$""")

    /** What the relay's `kind` field should say for this input. Mirrors bharosa.appcheck.detect_kind. */
    fun kindOf(content: String): String {
        val t = content.trim()
        return when {
            UPI_ONLY.matches(t) -> "qr"
            URL_ONLY.matches(t) -> "url"
            else -> "msg"
        }
    }

    /** Query parameters of a upi:// link, decoded. Empty map if it is not a upi:// link. */
    fun params(uri: String): Map<String, String> {
        val t = uri.trim()
        if (!t.lowercase().startsWith("upi://")) return emptyMap()
        val q = t.substringAfter('?', "")
        if (q.isEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in q.split('&')) {
            if (pair.isEmpty()) continue
            val k = decode(pair.substringBefore('=')).lowercase()
            val v = decode(pair.substringAfter('=', ""))
            if (k.isNotEmpty()) out[k] = v // last one wins, like the relay's parse_qsl
        }
        return out
    }

    /** The action part of upi://<action>?..., lowercased ("pay", "mandate", ...). */
    fun action(uri: String): String? {
        val t = uri.trim()
        if (!t.lowercase().startsWith("upi://")) return null
        return t.substring(6).substringBefore('?').trimEnd('/').lowercase()
    }

    /**
     * True only for a upi://pay link with a valid-looking payee UPI ID. This is the only kind of
     * link Bharosa will ever hand to the system's UPI app chooser.
     */
    fun isPayLink(uri: String): Boolean {
        if (action(uri) != "pay") return false
        val pa = params(uri)["pa"] ?: return false
        return VPA.matches(pa.trim())
    }

    /** The first upi:// link in a piece of shared text, if any. */
    fun firstUpiLink(text: String): String? = UPI_IN_TEXT.find(text)?.value?.trimEnd('.', ',', ')', ']')

    /**
     * What to check when text is shared to Bharosa. A share that is only a upi:// link or only a
     * URL is checked as that; anything longer is checked as a message (the relay still checks every
     * link and UPI ID inside it).
     */
    fun checkableFromShare(subject: String?, text: String?): String? {
        val body = listOfNotNull(subject?.trim(), text?.trim()).filter { it.isNotEmpty() }
            .distinct().joinToString("\n")
        return body.ifBlank { null }
    }

    /** Same digest the relay stores as input_sha256 for a QR check (sha256 of the trimmed link). */
    fun sha256(text: String): String {
        val d = MessageDigest.getInstance("SHA-256").digest(text.trim().toByteArray(Charsets.UTF_8))
        return d.joinToString("") { "%02x".format(it) }
    }

    /** Display form of a UPI ID, same as the relay's mask_vpa: "ra***@okaxis". */
    fun maskVpa(vpa: String): String {
        val at = vpa.indexOf('@')
        if (at < 0) return "<UPI_ID>"
        return vpa.substring(0, at).take(2) + "***" + vpa.substring(at)
    }

    private fun decode(s: String): String = try {
        URLDecoder.decode(s, "UTF-8") // "+" becomes a space, as in the relay
    } catch (e: IllegalArgumentException) {
        s
    }
}
