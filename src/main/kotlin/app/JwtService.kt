package app

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import java.util.Date

class JwtService(
    secret: String
) {
    private val signer = MACSigner(secret)
    private val verifier = MACVerifier(secret)

    /**
     * Create jwt token
     *
     * @userId - user id
     * @userName - user name
     * @roles - list of user roles
     * @ttl - token time to live in seconds
     * @jti - token id (ObjectID in hex text if used with MongoDB)
     *
     * JWT claims
     * sub - user_id
     * exp - expiration time (UTC, milliseconds)
     * jti - token id
     * roles - list of roles
     * name - user_name
     */
    fun create(userId: String,
               userName: String,
               roles: List<String>,
               ttl: Int,
               jti: String): String {
        val claimsSet = JWTClaimsSet.Builder()
            .subject(userId)
            .expirationTime(Date(Date().time + ttl * 1000))
            .jwtID(jti)
            .claim("name", userName)
            .claim("roles", roles)
            .build()

        val signedJWT = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claimsSet)

        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    /**
     * Verify [jwt] token. Check signature and expiration time
     */
    fun verify(jwt: String): Boolean {
        val signedJwt = SignedJWT.parse(jwt)
        return signedJwt.verify(verifier) &&
            Date().before(signedJwt.jwtClaimsSet.expirationTime)
    }
}
