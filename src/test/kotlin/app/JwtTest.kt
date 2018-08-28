package app

import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.SignedJWT
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import org.openjdk.jmh.annotations.Benchmark
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
    fun `verify fail`() {
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
