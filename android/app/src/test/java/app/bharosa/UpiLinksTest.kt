package app.bharosa

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UpiLinksTest {
    private val milk = "upi://pay?pa=sharma.dairy@okaxis&pn=Sharma%20Dairy&am=60"

    @Test fun kindMatchesTheRelay() {
        assertEquals("qr", UpiLinks.kindOf("  $milk "))
        assertEquals("url", UpiLinks.kindOf("https://sbi-kyc-update.example/login"))
        assertEquals("url", UpiLinks.kindOf("www.example.com"))
        assertEquals("msg", UpiLinks.kindOf("Your KYC expires today, click https://x.example"))
    }

    @Test fun parsesAndDecodesParams() {
        val p = UpiLinks.params(milk)
        assertEquals("sharma.dairy@okaxis", p["pa"])
        assertEquals("Sharma Dairy", p["pn"])
        assertEquals("60", p["am"])
        assertEquals("pay", UpiLinks.action(milk))
        assertEquals("Sharma Dairy", UpiLinks.params("upi://pay?PA=a@b&pn=Sharma+Dairy")["pn"])
        assertTrue(UpiLinks.params("https://example.com?pa=x@y").isEmpty())
    }

    @Test fun onlyWellFormedPayLinksAreHandedOff() {
        assertTrue(UpiLinks.isPayLink(milk))
        assertTrue(UpiLinks.isPayLink("UPI://pay/?pa=shop.demo@okicici"))
        assertFalse(UpiLinks.isPayLink("upi://mandate?pa=shop.demo@okicici&am=1"))
        assertFalse(UpiLinks.isPayLink("upi://pay?pn=NoPayee&am=10"))
        assertFalse(UpiLinks.isPayLink("upi://pay?pa=not a vpa"))
        assertFalse(UpiLinks.isPayLink("intent://pay?pa=shop.demo@okicici"))
        assertFalse(UpiLinks.isPayLink("https://pay.example/?pa=shop.demo@okicici"))
    }

    @Test fun findsUpiLinksInSharedText() {
        val msg = "Sir pay here (upi://pay?pa=rewards.demo@okhdfcbank&am=4999). Thanks"
        assertEquals("upi://pay?pa=rewards.demo@okhdfcbank&am=4999", UpiLinks.firstUpiLink(msg))
        assertNull(UpiLinks.firstUpiLink("no links here"))
    }

    @Test fun shareTextJoinsSubjectAndBody() {
        assertEquals("KYC alert\nUpdate now at https://x.example",
            UpiLinks.checkableFromShare("KYC alert", "Update now at https://x.example"))
        assertEquals("same", UpiLinks.checkableFromShare("same", "same"))
        assertNull(UpiLinks.checkableFromShare(null, "   "))
    }

    @Test fun sha256MatchesTheRelaysInputHash() {
        // hashlib.sha256(milk.encode()).hexdigest(), as bharosa.pipeline.check_qr stores it
        assertEquals("963d5468f86bd6fcc6d5d84a0e622a44c5dba257a8bca7ba622f679ba0d45022", UpiLinks.sha256(" $milk\n"))
    }

    @Test fun masksPayeeLikeTheRelay() {
        assertEquals("sh***@okaxis", UpiLinks.maskVpa("sharma.dairy@okaxis"))
        assertEquals("<UPI_ID>", UpiLinks.maskVpa("nope"))
    }
}
