package app

import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Test
import java.util.Date

class JwtTest {
    companion object {
        private const val secret = "3cb394ce4e48791d0555cc56e64e714f"
        private val jwtService = JwtService(secret)
    }

    @Test
    fun create() {
        val userId = "e28dae05786454e083904b654614d59b"
        val userName = "John Doe"
        val roles = listOf("USER", "ADMIN")
        val jti = "f93a9003f9c1d747e56d732fee1af006"
        val ttl = 60

        val jwt = jwtService.create(
            userId = userId,
            userName = userName,
            roles = roles,
            ttl = ttl,
            jti = jti)

        val signedJwt = SignedJWT.parse(jwt)
        val verifier = MACVerifier(secret)

        assertTrue(signedJwt.verify(verifier))
        assertEquals(userId, signedJwt.jwtClaimsSet.subject)
        assertEquals(userName, signedJwt.jwtClaimsSet.getClaim("name"))
        assertEquals(roles, signedJwt.jwtClaimsSet.getClaim("roles"))
        assertEquals(jti, signedJwt.jwtClaimsSet.jwtid)
        assertTrue(Date().before(signedJwt.jwtClaimsSet.expirationTime))
    }

    @Test
    fun verify() {
        val userId = "e28dae05786454e083904b654614d59b"
        val userName = "John Doe"
        val roles = listOf("USER", "ADMIN")
        val jti = "f93a9003f9c1d747e56d732fee1af006"
        val ttl = 60

        val jwt = jwtService.create(
            userId = userId,
            userName = userName,
            roles = roles,
            ttl = ttl,
            jti = jti)

        assertTrue(jwtService.verify(jwt))
    }

    @Test
    fun `verify fail on signature`() {
        val userId = "e28dae05786454e083904b654614d59b"
        val userName = "John Doe"
        val roles = listOf("USER", "ADMIN")
        val jti = "f93a9003f9c1d747e56d732fee1af006"
        val ttl = 1

        val jwt = jwtService.create(
            userId = userId,
            userName = userName,
            roles = roles,
            ttl = ttl,
            jti = jti)

        val jwtParts = jwt.split('.')
        val signature = jwtParts[2]
        val brokenSignature = (signature.first() + 1) +
            signature.takeLast(signature.length - 1)
        val brokenJwt = "${jwtParts[0]}.${jwtParts[1]}.$brokenSignature"

        assertEquals(jwt.length, brokenJwt.length)
        assertNotEquals(jwt, brokenJwt)

        assertFalse(jwtService.verify(brokenJwt))
    }

    @Test
    fun `verify fail on ttl`() {
        val userId = "e28dae05786454e083904b654614d59b"
        val userName = "John Doe"
        val roles = listOf("USER", "ADMIN")
        val jti = "f93a9003f9c1d747e56d732fee1af006"
        val ttl = 1

        val jwt = jwtService.create(
            userId = userId,
            userName = userName,
            roles = roles,
            ttl = ttl,
            jti = jti)

        Thread.sleep(1 * 1000 + 1)

        assertFalse(jwtService.verify(jwt))
    }
}
