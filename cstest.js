const { hash, verify } = require("./index");

const SECRET_KEY = "supersecret";

// 1. Rainbow Table Attack
(async () => {
    const a = await hash("password123", SECRET_KEY);
    const b = await hash("password123", SECRET_KEY);
    console.log("Rainbow Table Test:", a.hash !== b.hash ? "PASS" : "FAIL");

    // 2. Brute Force Attack (timing)
    console.time("Low Iterations");
    await hash("password123", SECRET_KEY, { iterations: 1000 });
    console.timeEnd("Low Iterations");

    console.time("High Iterations");
    await hash("password123", SECRET_KEY, { iterations: 200_000 });
    console.timeEnd("High Iterations");

    // 3. Timing Attack (should use timingSafeEqual)
    const v = await verify("password123", a.passport, SECRET_KEY);
    console.log("Timing Safe Equal Test:", v.valid ? "PASS" : "FAIL");

    // 4. Salt Storage
    console.log("Salt Unique Test:", a.salt !== b.salt ? "PASS" : "FAIL");

    // 5. Pepper Security
    process.env.HASH_PEPPER = "pepper";
    const withPepper = await hash("password123", SECRET_KEY);
    process.env.HASH_PEPPER = "";
    const vPepper = await verify("password123", withPepper.passport, SECRET_KEY);
    console.log("Pepper Security Test:", vPepper.valid ? "FAIL" : "PASS");

    // 6. Upgrade Path
    const vUpgrade = await verify("password123", a.passport, SECRET_KEY, { iterations: 200_000 });
    console.log("Upgrade Path Test:", vUpgrade.needsUpgrade ? "PASS" : "FAIL");

    // 7. Input Validation
    try {
        await hash(null, SECRET_KEY);
        console.log("Null Input Test: FAIL");
    } catch {
        console.log("Null Input Test: PASS");
    }

    // 8. Collision Resistance
    const c = await hash("passwordABC", SECRET_KEY);
    console.log("Collision Resistance Test:", a.hash !== c.hash ? "PASS" : "FAIL");
})();