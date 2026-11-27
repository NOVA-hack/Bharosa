package app.bharosa

import android.os.Bundle
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity

/** Relay address, language, and pairing this phone as the parent or a guardian. */
class SetupActivity : AppCompatActivity() {
    private lateinit var prefs: Prefs
    private lateinit var root: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = Prefs(this)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Setup"
        build()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun build() {
        root = page()
        text(root, "Relay", 18f, bold = true, top = 0)
        text(root, "Run `bharosa relay --host 0.0.0.0 --port 8765` on the laptop. The emulator reaches it at http://10.0.2.2:8765; a phone on the same Wi-Fi uses http://<laptop IP>:8765.",
            13f, color = muted())
        val url = input(root, "http://10.0.2.2:8765", prefs.relayUrl)
        val status = text(root, "", 13f, color = muted())
        button(root, "Save and test connection", outlined = true) {
            prefs.relayUrl = url.text.toString()
            status.text = "Testing…"
            background({ prefs.api().health() }) { r ->
                status.text = r.fold({ "Connected: relay ${it.optString("version")}" }, { it.friendly() })
            }
        }

        text(root, "Language for warnings", 18f, bold = true, top = 20)
        val langRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        root.addView(langRow)
        for ((code, label) in listOf("en" to "English", "hi" to "हिन्दी", "kn" to "ಕನ್ನಡ")) {
            val col = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            }
            langRow.addView(col)
            button(col, (if (prefs.lang == code) "✓ " else "") + label, outlined = prefs.lang != code) {
                prefs.lang = code
                build()
            }
        }

        if (prefs.token != null) {
            text(root, "This phone", 18f, bold = true, top = 20)
            text(root, "Paired as ${prefs.role} (${prefs.name}).")
            button(root, "Unpair this phone", outlined = true) {
                AlertDialog.Builder(this).setTitle("Unpair?")
                    .setMessage("This phone forgets its family link. The family's cases stay on the relay.")
                    .setPositiveButton("Unpair") { _, _ -> prefs.forget(); build() }
                    .setNegativeButton("Cancel", null).show()
            }
            return
        }

        text(root, "Family review", 18f, bold = true, top = 20)
        val name = input(root, "Your name")

        val parent = card(root)
        text(parent, "I am the parent", 16f, bold = true, top = 0)
        text(parent, "Risky payments you scan will wait for a guardian to approve.", 13f, color = muted())
        button(parent, "Create our family") {
            val n = name.text.toString().trim().ifEmpty { return@button toast("Enter your name first") }
            prefs.relayUrl = url.text.toString()
            background({ BharosaApi(prefs.relayUrl).createFamily(n, prefs.lang) }) { r ->
                r.onSuccess { m ->
                    prefs.saveMembership(m)
                    AlertDialog.Builder(this).setTitle("Family created")
                        .setMessage("Pairing code for your guardian:\n\n${m.pairCode}\n\nThey enter it in Bharosa Setup on their phone, or send /join ${m.pairCode} <name> to the Bharosa bot on Telegram or WhatsApp. It works once, for 10 minutes.")
                        .setPositiveButton("OK") { _, _ -> finish() }.setCancelable(false).show()
                }.onFailure { toast(it.friendly()) }
            }
        }

        val guardian = card(root)
        text(guardian, "I am a guardian", 16f, bold = true, top = 0)
        text(guardian, "Use the pairing code from the parent's Bharosa (app or bot).", 13f, color = muted())
        val code = input(guardian, "Pairing code, e.g. ab12-123456")
        button(guardian, "Join family") {
            val n = name.text.toString().trim().ifEmpty { return@button toast("Enter your name first") }
            val c = code.text.toString().trim().ifEmpty { return@button toast("Enter the pairing code") }
            prefs.relayUrl = url.text.toString()
            background({ BharosaApi(prefs.relayUrl).joinFamily(c, n, prefs.lang) }) { r ->
                r.onSuccess { m -> prefs.saveMembership(m); toast("Joined. Review requests will appear on the home screen."); finish() }
                    .onFailure { toast(it.friendly()) }
            }
        }
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()
}
