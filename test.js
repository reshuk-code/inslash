const { hash, verify } = require("./script");

const SECRET_KEY = process.env.HASH_SECRET || "abcd";

// create hash
(async () => {
    const result = await hash("Happy", SECRET_KEY, {
        iterations: 150_000
    });

    console.log(result);

    // verify
    const verifyResult = await verify(
        "Happy",
        result.passport, // <-- use passport, not salt/hash
        SECRET_KEY,
        { iterations: result.iterations }
    );

    console.log(verifyResult); // { valid: true, needsUpgrade: false, upgradedPassport: null }
})();
