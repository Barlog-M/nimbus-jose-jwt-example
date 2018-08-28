package app

import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.runner.Runner
import java.util.UUID
import java.util.concurrent.ThreadLocalRandom
import org.openjdk.jmh.runner.options.OptionsBuilder
import java.util.concurrent.TimeUnit

open class Performance {
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    open fun jwt(): String {
        val jwtService = JwtService(UUID.randomUUID().toString())
        return jwtService.create(
            userId = UUID.randomUUID().toString(),
            userName = "John Doe",
            roles = listOf("USER", "ADMIN"),
            ttl = ThreadLocalRandom.current().nextInt(60, 999),
            jti = UUID.randomUUID().toString())
    }
}

fun main(vararg args: String) {
    val opt = OptionsBuilder()
        .include(Performance::class.java.simpleName)
        .forks(1)
        .build()

    Runner(opt).run()
}
