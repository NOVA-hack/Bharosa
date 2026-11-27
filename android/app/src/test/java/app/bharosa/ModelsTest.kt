package app.bharosa

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Parses real relay responses (written by scripts/make_android_fixtures.py). */
class ModelsTest {
    private fun fixture(name: String) =
        JSONObject(javaClass.classLoader!!.getResource(name)!!.readText())

    @Test fun riskyQrIsHeldWithReasons() {
        val r = CheckResult.parse(fixture("check_held.json"))
        assertEquals("high", r.riskLevel)
        assertEquals("hold", r.action)
        assertEquals("held", r.state)
        assertTrue(r.isPayment)
        assertEquals("re***@okhdfcbank", r.payeeMasked)
        assertEquals(4999.0, r.amount!!, 0.001)
        assertTrue(r.reasons.any { it.ruleId == "QR-RECEIVE-MONEY" && it.text.isNotBlank() })
        assertTrue(r.truthCards.isNotEmpty())
        assertNotNull(r.message)
        assertEquals(1, r.guardiansNotified)
        assertEquals(UpiLinks.sha256(
            "upi://pay?pa=rewards.demo@okhdfcbank&pn=SBI%20Rewards&am=4999&tn=receive%20cashback"), r.inputSha256)
    }

    @Test fun safeQrMayProceed() {
        val r = CheckResult.parse(fixture("check_allowed.json"))
        assertEquals("low", r.riskLevel)
        assertEquals("proceed", r.action)
        assertEquals("allowed", r.state)
        assertNull(r.queueError)
    }

    @Test fun guardianSeesMaskedCase() {
        val c = FamilyCase.parse(fixture("case_held.json"))
        assertEquals("held", c.state)
        assertEquals("Amma", c.parentName)
        assertTrue(c.maskedContent.contains("<UPI"))
        assertTrue(c.reasons.isNotEmpty())
        assertNotNull(c.expiresAt)
        assertNotNull(c.inputSha256)
    }

    @Test fun relayErrorsBecomeReadable() {
        val e = BharosaApi.errorFrom(409, """{"error":"conflict","detail":"case is blocked; Bharosa will not hand it off"}""")
        assertEquals("conflict", e.code)
        assertEquals("case is blocked; Bharosa will not hand it off", e.message)
        val v = BharosaApi.errorFrom(422, """{"detail":[{"msg":"String should have at least 1 character"}]}""")
        assertEquals("String should have at least 1 character", v.message)
        assertEquals("HTTP 502", BharosaApi.errorFrom(502, "").message)
    }
}
