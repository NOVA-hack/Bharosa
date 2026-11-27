package app.bharosa

import android.app.Activity
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import java.util.concurrent.Executors

/** Small view helpers so every screen is built the same way, in code, with no layout XML. */

private val io = Executors.newCachedThreadPool()

/** Run [work] off the main thread, then [done] on it with the result or the error. */
fun <T> Activity.background(work: () -> T, done: (Result<T>) -> Unit) {
    io.execute {
        val r = runCatching(work)
        runOnUiThread { if (!isFinishing && !isDestroyed) done(r) }
    }
}

fun Throwable.friendly(): String = when (this) {
    is ApiError -> message ?: "The relay said no ($code)"
    is java.net.ConnectException, is java.net.SocketTimeoutException, is java.net.UnknownHostException ->
        "Cannot reach the Bharosa relay. Check the relay address in Setup and that `bharosa relay --host 0.0.0.0` is running."
    else -> message ?: javaClass.simpleName
}

fun Activity.dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

/** A scrolling vertical page. Returns the column to add views to. */
fun Activity.page(): LinearLayout {
    val col = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(20), dp(16), dp(20), dp(32))
    }
    setContentView(ScrollView(this).apply { addView(col) })
    return col
}

fun Activity.text(parent: ViewGroup, s: CharSequence, size: Float = 16f, bold: Boolean = false,
                  color: Int? = null, top: Int = 8): TextView =
    TextView(this).apply {
        text = s
        textSize = size
        if (bold) setTypeface(typeface, Typeface.BOLD)
        if (color != null) setTextColor(color)
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(top) }
        parent.addView(this)
    }

fun Activity.button(parent: ViewGroup, label: String, outlined: Boolean = false, onClick: () -> Unit): Button {
    val b = if (outlined) MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle)
    else MaterialButton(this)
    b.text = label
    b.isAllCaps = false
    b.textSize = 16f
    b.layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(10) }
    b.setOnClickListener { onClick() }
    parent.addView(b)
    return b
}

fun Activity.input(parent: ViewGroup, hint: String, value: String = "", multiline: Boolean = false): EditText =
    EditText(this).apply {
        this.hint = hint
        setText(value)
        if (!multiline) isSingleLine = true else {
            minLines = 3
            gravity = Gravity.TOP or Gravity.START
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(8) }
        parent.addView(this)
    }

/** A rounded box; returns its inner column. */
fun Activity.card(parent: ViewGroup, bg: Int = ContextCompat.getColor(this, R.color.card_bg),
                  border: Int? = null): LinearLayout {
    val box = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(16), dp(10), dp(16), dp(14))
        background = GradientDrawable().apply {
            cornerRadius = dp(12).toFloat()
            setColor(bg)
            if (border != null) setStroke(dp(2), border)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(14) }
    }
    parent.addView(box)
    return box
}

fun Activity.riskColors(level: String): Pair<Int, Int> = when (level) {
    "low" -> ContextCompat.getColor(this, R.color.risk_low) to ContextCompat.getColor(this, R.color.risk_low_bg)
    "high" -> ContextCompat.getColor(this, R.color.risk_high) to ContextCompat.getColor(this, R.color.risk_high_bg)
    else -> ContextCompat.getColor(this, R.color.risk_medium) to ContextCompat.getColor(this, R.color.risk_medium_bg)
}

fun riskIcon(level: String) = when (level) {
    "low" -> "🟢"
    "high" -> "🔴"
    else -> "🟠"
}

fun Activity.muted(): Int = ContextCompat.getColor(this, R.color.muted)

/** The "Why" list: one line per reason, with the masked evidence the rule matched. */
fun Activity.reasonList(parent: ViewGroup, reasons: List<Reason>) {
    val shown = reasons.filter { it.severity != "info" }.ifEmpty { reasons }
    if (shown.isEmpty()) return
    text(parent, "Why", 15f, bold = true, top = 12)
    for (r in shown) {
        val line = StringBuilder("• ").append(r.text)
        if (!r.evidence.isNullOrBlank()) line.append("  (").append(r.evidence.take(80)).append(")")
        text(parent, line, 15f, top = 6)
        text(parent, "${r.ruleId} · ${r.severity}", 12f, color = muted(), top = 0)
    }
}

fun View.show(visible: Boolean) {
    visibility = if (visible) View.VISIBLE else View.GONE
}

fun formatAmount(a: Double?): String? = a?.let { if (it % 1.0 == 0.0) "₹${it.toLong()}" else "₹%.2f".format(it) }
