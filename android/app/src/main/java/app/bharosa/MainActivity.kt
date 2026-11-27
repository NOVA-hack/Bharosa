package app.bharosa

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

/**
 * Home. A parent scans a QR or pastes a message and sees payments waiting for family. A guardian
 * sees the review queue (the same queue the Telegram and WhatsApp bots push from) and decides.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private lateinit var root: LinearLayout
    private var queueBox: LinearLayout? = null
    private val handler = Handler(Looper.getMainLooper())
    private var resumed = false

    private val scan = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@registerForActivityResult
        startActivity(CheckActivity.forContent(this, text, if (UpiLinks.action(text) != null) "qr" else UpiLinks.kindOf(text)))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        build()
        refreshLoop()
    }

    override fun onPause() {
        resumed = false
        handler.removeCallbacksAndMessages(null)
        super.onPause()
    }

    private fun build() {
        root = page()
        text(root, "Bharosa", 28f, bold = true, top = 0)
        val who = when {
            prefs.isParent -> "Parent: ${prefs.name}"
            prefs.isGuardian -> "Guardian: ${prefs.name}"
            else -> "Not paired with a family yet"
        }
        text(root, "$who · ${prefs.relayUrl}", 13f, color = muted(), top = 2)

        if (!prefs.isGuardian) {
            button(root, "📷  Scan a payment QR") { startScan() }
            val box = card(root)
            text(box, "Check a message or link", 16f, bold = true, top = 0)
            val field = input(box, "Paste an SMS, WhatsApp message, link or upi:// link", multiline = true)
            button(box, "Check") {
                val t = field.text.toString().trim()
                if (t.isNotEmpty()) startActivity(CheckActivity.forContent(this, t, UpiLinks.kindOf(t)))
            }
            text(root, "Tip: in WhatsApp or Messages, long-press a message, tap Share, then pick Bharosa.", 13f,
                color = muted())
        }

        if (prefs.isParent) {
            text(root, "Waiting for family", 18f, bold = true, top = 20)
            queueBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            root.addView(queueBox)
            button(root, "Pairing code for a guardian", outlined = true) { pairCode() }
        } else if (prefs.isGuardian) {
            text(root, "Waiting for your decision", 18f, bold = true, top = 20)
            queueBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
            root.addView(queueBox)
            button(root, "Lift Emergency Stop", outlined = true) { unlock() }
        }

        if (prefs.token != null) {
            val (fg, _) = riskColors("high")
            button(root, "🛑  Emergency Stop") { emergencyStop() }.backgroundTintList =
                android.content.res.ColorStateList.valueOf(fg)
        }
        button(root, if (prefs.token == null) "Set up family review" else "Setup", outlined = true) {
            startActivity(Intent(this, SetupActivity::class.java))
        }
        text(root, "Bharosa never makes a payment and cannot promise something is safe. Report fraud on 1930.",
            12f, color = muted(), top = 18)
    }

    private fun startScan() {
        scan.launch(ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Point the camera at the payment QR")
            setBeepEnabled(false)
            setOrientationLocked(false)
        })
    }

    // ---- the queue -------------------------------------------------------------------

    private fun refreshLoop() {
        if (!resumed || prefs.token == null) return
        refreshQueue()
        handler.postDelayed({ refreshLoop() }, if (prefs.isGuardian) 5000L else 8000L)
    }

    private fun refreshQueue() {
        val box = queueBox ?: return
        if (prefs.isGuardian) {
            background({ prefs.api().heldCases() }) { r ->
                box.removeAllViews()
                r.onSuccess { cases ->
                    if (cases.isEmpty()) text(box, "Nothing to review right now.", 15f, color = muted())
                    for (c in cases) caseRow(box, c) { startActivity(ReviewActivity.forCase(this, c.id)) }
                }.onFailure { text(box, it.friendly(), 14f, color = muted()) }
            }
        } else if (prefs.isParent) {
            val ids = prefs.pendingIds()
            background({ ids.mapNotNull { id -> runCatching { prefs.api().case(id) }.getOrNull() } }) { r ->
                box.removeAllViews()
                val cases = r.getOrDefault(emptyList())
                if (cases.isEmpty()) text(box, "No payments are waiting.", 15f, color = muted())
                for (c in cases) caseRow(box, c) { startActivity(CheckActivity.forCase(this, c.id)) }
            }
        }
    }

    private fun caseRow(parent: LinearLayout, c: FamilyCase, onClick: () -> Unit) {
        val (fg, bg) = riskColors(c.riskLevel)
        val box = card(parent, bg)
        val title = listOfNotNull(c.parentName?.takeIf { prefs.isGuardian }, c.payeeMasked, formatAmount(c.amount))
            .joinToString(" · ").ifEmpty { c.maskedContent.take(60) }
        text(box, "${riskIcon(c.riskLevel)} $title", 16f, bold = true, color = fg, top = 0)
        text(box, "${c.riskLevel.uppercase()} ${c.score}/100 · ${c.state} · ${c.id}", 12f, color = muted())
        box.setOnClickListener { onClick() }
    }

    // ---- family actions --------------------------------------------------------------

    private fun pairCode() {
        background({ prefs.api().newPairCode() }) { r ->
            r.onSuccess { code ->
                AlertDialog.Builder(this).setTitle("Pairing code")
                    .setMessage("$code\n\nThe guardian enters this in Bharosa Setup, or sends /join $code <name> to the Bharosa bot. It works once, for 10 minutes.")
                    .setPositiveButton("OK", null).show()
            }.onFailure { toast(it.friendly()) }
        }
    }

    private fun emergencyStop() {
        AlertDialog.Builder(this).setTitle("Emergency Stop?")
            .setMessage("This locks every payment waiting for review and tells your family. Use it if someone is pressuring you right now.")
            .setPositiveButton("Stop everything") { _, _ ->
                background({ prefs.api().emergencyStop("pressed in the Android app") }) { r ->
                    r.onSuccess { toast("Emergency Stop is on. Call 1930 to report fraud.") }
                        .onFailure { toast(it.friendly()) }
                }
            }.setNegativeButton("Cancel", null).show()
    }

    private fun unlock() {
        background({ prefs.api().unlock() }) { r ->
            r.onSuccess { toast("Emergency Stop lifted.") }.onFailure { toast(it.friendly()) }
        }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
