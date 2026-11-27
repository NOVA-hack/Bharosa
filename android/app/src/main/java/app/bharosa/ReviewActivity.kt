package app.bharosa

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

/** A guardian's view of one held case: masked content, the reasons, Approve or Block. */
class ReviewActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private lateinit var root: LinearLayout
    private lateinit var caseId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        caseId = intent.getStringExtra(EXTRA_CASE_ID) ?: return finish()
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Review request"
        root = page()
        text(root, "Loading…")
        load()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun load() {
        background({ prefs.api().case(caseId) }) { r ->
            r.onSuccess { render(it) }.onFailure {
                root.removeAllViews()
                text(root, it.friendly())
                button(root, "Try again") { load() }
            }
        }
    }

    private fun render(c: FamilyCase) {
        root.removeAllViews()
        val (fg, bg) = riskColors(c.riskLevel)
        val banner = card(root, bg, fg)
        text(banner, "🔔 From ${c.parentName ?: "your family"}", 18f, bold = true, top = 0)
        text(banner, "${riskIcon(c.riskLevel)} ${c.riskLevel.uppercase()} · score ${c.score}/100", 16f, bold = true,
            color = fg)
        val payee = listOfNotNull(c.payeeMasked?.let { "Payee $it" }, formatAmount(c.amount))
        if (payee.isNotEmpty()) text(banner, payee.joinToString(" · "), 15f)

        text(root, "What they received (personal details masked)", 14f, bold = true, top = 14)
        val box = card(root)
        text(box, c.maskedContent.take(800), 14f, top = 0)
        reasonList(root, c.reasons)
        c.expiresAt?.let {
            val mins = ((it - System.currentTimeMillis() / 1000.0) / 60).toInt().coerceAtLeast(0)
            text(root, "Waits about $mins min for a decision, then expires unpaid.", 13f, color = muted(), top = 12)
        }

        if (c.state != "held") {
            text(root, "This case is already ${c.state}.", 16f, bold = true, top = 16)
            button(root, "Back") { finish() }
            return
        }
        val note = input(root, "Note for them (optional), e.g. \"Call me first\"")
        button(root, "⛔  Block") { decide(false, note.text.toString()) }
        button(root, "✅  Approve", outlined = true) {
            if (c.riskLevel == "high") {
                AlertDialog.Builder(this).setTitle("Approve a high-risk payment?")
                    .setMessage("Bharosa's checks say this looks like a scam. Approve only if you have spoken to them and know the payee.")
                    .setPositiveButton("Approve anyway") { _, _ -> decide(true, note.text.toString()) }
                    .setNegativeButton("Cancel", null).show()
            } else decide(true, note.text.toString())
        }
    }

    private fun decide(approve: Boolean, note: String) {
        background({ prefs.api().decide(caseId, approve, note) }) { r ->
            r.onSuccess {
                Toast.makeText(this, if (approve) "Approved" else "Blocked", Toast.LENGTH_SHORT).show()
                finish()
            }.onFailure { Toast.makeText(this, it.friendly(), Toast.LENGTH_LONG).show(); load() }
        }
    }

    companion object {
        const val EXTRA_CASE_ID = "app.bharosa.REVIEW_CASE_ID"
        fun forCase(ctx: Context, caseId: String) =
            Intent(ctx, ReviewActivity::class.java).putExtra(EXTRA_CASE_ID, caseId)
    }
}
