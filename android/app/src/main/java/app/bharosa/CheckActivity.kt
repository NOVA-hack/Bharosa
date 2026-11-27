package app.bharosa

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

/**
 * One check, start to finish.
 *
 * Input arrives from an in-app scan or paste, from a upi:// link another app opened (Bharosa is a
 * upi:// handler), or from text shared to Bharosa. The relay decides the risk. Then:
 *
 * - proceed: a upi://pay link is handed to the phone's UPI app chooser, prefilled
 * - hold:    the payment waits for a guardian (decided in this app or the Telegram/WhatsApp bot);
 *            the raw link stays on this phone and is handed off only once the case is approved
 * - stop:    Emergency Stop is on, nothing is handed off
 * - warn:    not paired with a family; a risky payment is not handed off
 */
class CheckActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private lateinit var root: LinearLayout
    private lateinit var actions: LinearLayout
    private val handler = Handler(Looper.getMainLooper())
    private var polling = false

    private var content: String = ""
    private var caseId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = getString(R.string.check_with_bharosa)
        root = page()

        val resume = intent.getStringExtra(EXTRA_CASE_ID)
        if (resume != null) {
            caseId = resume
            content = prefs.pendingLink(resume) ?: ""
            text(root, "Payment waiting for your family", 20f, bold = true)
            text(root, "Case $resume", 13f, color = muted())
            actions = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            root.addView(actions)
            startPolling()
            return
        }

        val (input, kind) = readInput() ?: run {
            text(root, "Nothing to check", 20f, bold = true)
            text(root, "Share a message or link to Bharosa, open a upi:// link with it, or scan a QR from the home screen.")
            button(root, "Open Bharosa") { startActivity(Intent(this, MainActivity::class.java)); finish() }
            return
        }
        content = input
        text(root, "Checking…", 20f, bold = true)
        text(root, preview(input), 14f, color = muted())
        runCheck(input, kind)
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    override fun onDestroy() {
        polling = false
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun readInput(): Pair<String, String>? {
        val i = intent
        return when {
            i.action == Intent.ACTION_VIEW && i.data?.scheme.equals("upi", ignoreCase = true) ->
                i.dataString?.let { it to "qr" }
            i.action == Intent.ACTION_SEND -> UpiLinks.checkableFromShare(
                i.getStringExtra(Intent.EXTRA_SUBJECT), i.getStringExtra(Intent.EXTRA_TEXT)
            )?.let { it to UpiLinks.kindOf(it) }
            i.getStringExtra(EXTRA_CONTENT) != null -> {
                val c = i.getStringExtra(EXTRA_CONTENT)!!
                c to (i.getStringExtra(EXTRA_KIND) ?: UpiLinks.kindOf(c))
            }
            else -> null
        }
    }

    private fun preview(s: String): String {
        // Show the payee masked even before the verdict comes back.
        if (UpiLinks.action(s) != null) {
            val p = UpiLinks.params(s)
            val bits = listOfNotNull(p["pa"]?.let { "Payee " + UpiLinks.maskVpa(it) }, p["pn"]?.let { "\"$it\"" },
                p["am"]?.toDoubleOrNull()?.let { formatAmount(it) })
            return "UPI payment request · " + bits.joinToString(" · ")
        }
        return if (s.length > 140) s.take(140) + "…" else s
    }

    // ---- the check -------------------------------------------------------------------

    private fun runCheck(input: String, kind: String) {
        background({ prefs.api().check(input, kind, prefs.lang) }) { r ->
            r.onSuccess { render(it) }.onFailure { showError(it) }
        }
    }

    private fun showError(e: Throwable) {
        root.removeAllViews()
        text(root, "Could not check this", 20f, bold = true)
        text(root, e.friendly())
        text(root, "Bharosa did not open any payment. If you were about to pay someone you do not know, stop and call family first.",
            14f, color = muted())
        button(root, "Try again") { recreate() }
        button(root, "Setup", outlined = true) { startActivity(Intent(this, SetupActivity::class.java)) }
    }

    private fun render(r: CheckResult) {
        caseId = r.caseId
        root.removeAllViews()
        val (fg, bg) = riskColors(r.riskLevel)
        val banner = card(root, bg, fg)
        text(banner, "${riskIcon(r.riskLevel)} ${r.headline}", 20f, bold = true, color = fg, top = 0)
        text(banner, "Risk ${r.riskLevel.uppercase()} · score ${r.score}/100", 14f, color = fg)
        val payee = listOfNotNull(r.payeeMasked?.let { "Payee $it" }, formatAmount(r.amount))
        if (payee.isNotEmpty()) text(banner, payee.joinToString(" · "), 15f)

        reasonList(root, r.reasons)
        r.truthCards.firstOrNull()?.let { c ->
            val box = card(root)
            text(box, "ⓘ ${c.text}", 14f, top = 0)
            text(box, "${c.source} · ${c.url}", 12f, color = muted())
        }
        r.codeWordPrompt?.let { text(root, "🔑 $it", 15f, bold = true, top = 14) }
        text(root, r.disclaimer, 14f, color = muted(), top = 14)
        if (r.maskSummary.isNotBlank()) text(root, "Personal details masked before saving: ${r.maskSummary}", 12f,
            color = muted())
        r.queueError?.let { text(root, "Family review is not available right now: $it", 13f, color = fg) }

        actions = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        root.addView(actions)
        val payLink = r.isPayment && UpiLinks.isPayLink(content)
        when (r.action) {
            "proceed" -> if (payLink) {
                button(actions, "Continue to UPI app") { handOff(r.caseId, paired = r.state == "allowed") }
                button(actions, "Cancel", outlined = true) { finish() }
            } else {
                button(actions, "Done") { finish() }
            }
            "hold" -> {
                if (payLink) prefs.rememberPending(r.caseId, content)
                r.message?.let { text(actions, "⏸ $it", 16f, bold = true, top = 16) }
                if (r.guardiansNotified == 0) text(actions,
                    "No guardian has joined your family yet. Open Setup on the home screen to get a pairing code.",
                    14f, color = fg)
                startPolling()
            }
            "stop" -> {
                text(actions, "🛑 ${r.message ?: "Emergency Stop is on."}", 16f, bold = true, color = fg, top = 16)
                button(actions, "Close") { finish() }
            }
            else -> {
                r.message?.let { text(actions, it, 16f, bold = true, color = fg, top = 16) }
                if (!prefs.isParent) text(actions,
                    "Pair Bharosa with your family in Setup so a guardian can review payments like this one.", 14f)
                button(actions, "Close") { finish() }
            }
        }
    }

    // ---- waiting for a guardian -----------------------------------------------------

    private fun startPolling() {
        if (polling) return
        polling = true
        val status = text(actions, "Waiting for your family to decide…", 15f, top = 12)
        button(actions, "Close (keep waiting in the background)", outlined = true) { finish() }
        val id = caseId ?: return
        val tick = object : Runnable {
            override fun run() {
                if (!polling) return
                background({ prefs.api().caseState(id) }) { r ->
                    r.onSuccess { state ->
                        when (state) {
                            "held", "checked" -> {
                                status.text = "Waiting for your family to decide…"
                                handler.postDelayed(this, POLL_MS)
                            }
                            else -> {
                                polling = false
                                decided(id, state)
                            }
                        }
                    }.onFailure {
                        status.text = "Still waiting. ${it.friendly()}"
                        handler.postDelayed(this, POLL_MS * 2)
                    }
                }
            }
        }
        handler.post(tick)
    }

    private fun decided(id: String, state: String) {
        actions.removeAllViews()
        val (okFg, okBg) = riskColors("low")
        val (badFg, badBg) = riskColors("high")
        when (state) {
            "approved" -> {
                val box = card(actions, okBg, okFg)
                text(box, "✅ Your family approved this payment.", 17f, bold = true, color = okFg, top = 0)
                background({ prefs.api().case(id) }) { r ->
                    r.getOrNull()?.approvalNote?.let { text(box, "Note: $it", 15f) }
                }
                val link = prefs.pendingLink(id) ?: content
                if (UpiLinks.isPayLink(link)) button(actions, "Continue to UPI app") { handOffApproved(id, link) }
                else button(actions, "Done") { finish() }
            }
            "blocked" -> {
                prefs.dropPending(id)
                val box = card(actions, badBg, badFg)
                text(box, "⛔ Your family blocked this. Do not pay.", 17f, bold = true, color = badFg, top = 0)
                background({ prefs.api().case(id) }) { r ->
                    r.getOrNull()?.approvalNote?.let { text(box, "Note: $it", 15f) }
                }
                text(actions, "If someone is pressuring you, hang up and call 1930 to report fraud.", 14f)
                button(actions, "Close") { finish() }
            }
            "expired" -> {
                prefs.dropPending(id)
                text(actions, "⏳ No one decided in time, so Bharosa did not open this payment. Check it again if you still need to pay.",
                    16f, bold = true, top = 16)
                button(actions, "Close") { finish() }
            }
            "stopped" -> {
                prefs.dropPending(id)
                text(actions, "🛑 Emergency Stop is on. Bharosa has locked this payment. Call 1930 to report fraud.",
                    16f, bold = true, color = badFg, top = 16)
                button(actions, "Close") { finish() }
            }
            else -> {
                text(actions, "This case is now \"$state\".", 16f, top = 16)
                button(actions, "Close") { finish() }
            }
        }
    }

    // ---- handing off to a UPI app ---------------------------------------------------

    private fun handOff(id: String, paired: Boolean) {
        if (!paired) {
            launchUpi(content)
            finish()
            return
        }
        background({ prefs.api().handoff(id) }) { r ->
            r.onSuccess { launchUpi(content); finish() }
                .onFailure { Toast.makeText(this, it.friendly(), Toast.LENGTH_LONG).show() }
        }
    }

    private fun handOffApproved(id: String, link: String) {
        background({
            val case = prefs.api().case(id)
            // Hand off exactly the link the guardian approved, nothing else.
            check(case.inputSha256 == null || case.inputSha256 == UpiLinks.sha256(link)) {
                "This link does not match the case your family approved."
            }
            prefs.api().handoff(id)
        }) { r ->
            r.onSuccess { prefs.dropPending(id); launchUpi(link); finish() }
                .onFailure { Toast.makeText(this, it.friendly(), Toast.LENGTH_LONG).show() }
        }
    }

    private fun launchUpi(link: String) {
        if (!launchUpiChooser(this, link)) {
            Toast.makeText(this, "No UPI app on this phone can open the payment.", Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        const val EXTRA_CONTENT = "app.bharosa.CONTENT"
        const val EXTRA_KIND = "app.bharosa.KIND"
        const val EXTRA_CASE_ID = "app.bharosa.CASE_ID"
        private const val POLL_MS = 3000L

        fun forContent(ctx: Context, content: String, kind: String) =
            Intent(ctx, CheckActivity::class.java).putExtra(EXTRA_CONTENT, content).putExtra(EXTRA_KIND, kind)

        fun forCase(ctx: Context, caseId: String) =
            Intent(ctx, CheckActivity::class.java).putExtra(EXTRA_CASE_ID, caseId)

        /**
         * Open Android's chooser with the upi:// link, leaving Bharosa itself out (it is also a
         * upi:// handler, and must not catch its own hand-off). Returns false if no UPI app exists.
         */
        @Suppress("DEPRECATION")
        fun launchUpiChooser(activity: Activity, link: String): Boolean {
            if (!UpiLinks.isPayLink(link)) return false
            val view = Intent(Intent.ACTION_VIEW, Uri.parse(link.trim()))
            val others = activity.packageManager.queryIntentActivities(view, 0)
                .filter { it.activityInfo.packageName != activity.packageName }
            if (others.isEmpty()) return false
            val chooser = Intent.createChooser(view, "Pay with").apply {
                putExtra(Intent.EXTRA_EXCLUDE_COMPONENTS,
                    arrayOf(ComponentName(activity, CheckActivity::class.java)))
            }
            activity.startActivity(chooser)
            return true
        }
    }
}
