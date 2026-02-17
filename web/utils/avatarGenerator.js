const crypto = require('crypto');

function generateAvatarSvg(seed = null) {
    if (!seed) {
        seed = crypto.randomBytes(16).toString('hex');
    }

    // Simple pseudo-random number generator based on seed
    let seedValue = 0;
    for (let i = 0; i < seed.length; i++) {
        seedValue += seed.charCodeAt(i);
    }

    const rng = () => {
        const x = Math.sin(seedValue++) * 10000;
        return x - Math.floor(x);
    };

    // Color palettes (Modern, Vibrant)
    const palettes = [
        ['#4F46E5', '#7C3AED', '#DB2777'], // Indigo-Purple-Pink
        ['#059669', '#10B981', '#34D399'], // Emerald
        ['#2563EB', '#3B82F6', '#60A5FA'], // Blue
        ['#DC2626', '#EF4444', '#F87171'], // Red
        ['#D97706', '#F59E0B', '#FBBF24'], // Amber
        ['#0D9488', '#14B8A6', '#2DD4BF'], // Teal
    ];

    const palette = palettes[Math.floor(rng() * palettes.length)];
    const bg = palette[0]; // Darkest as background
    const primary = palette[1];
    const secondary = palette[2];

    // Generate shapes (Particles/Orbs)
    let shapes = '';
    const numShapes = 3 + Math.floor(rng() * 5); // 3 to 7 shapes

    for (let i = 0; i < numShapes; i++) {
        const cx = Math.floor(rng() * 100);
        const cy = Math.floor(rng() * 100);
        const r = 10 + Math.floor(rng() * 40); // 10-50 radius
        const opacity = 0.3 + (rng() * 0.5); // 0.3 - 0.8
        const color = rng() > 0.5 ? primary : secondary;

        // Randomly choose circle or rect for variety (mostly circles for "particles")
        if (rng() > 0.2) {
            shapes += `<circle cx="${cx}%" cy="${cy}%" r="${r}%" fill="${color}" fill-opacity="${opacity}" />`;
        } else {
            // Rotate rectangles
            const w = r * 1.5;
            const h = r * 1.5;
            const rot = Math.floor(rng() * 360);
            shapes += `<rect x="${cx - w / 2}%" y="${cy - h / 2}%" width="${w}%" height="${h}%" fill="${color}" fill-opacity="${opacity}" transform="rotate(${rot}, ${cx}, ${cy})" />`;
        }
    }

    // Add some "stardust" (small dots)
    for (let i = 0; i < 10; i++) {
        const cx = Math.floor(rng() * 100);
        const cy = Math.floor(rng() * 100);
        const r = 1 + Math.floor(rng() * 2);
        shapes += `<circle cx="${cx}%" cy="${cy}%" r="${r}%" fill="white" fill-opacity="0.6" />`;
    }

    const svg = `
    <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid slice">
        <defs>
            <linearGradient id="grad-${seed.substring(0, 4)}" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" style="stop-color:${bg};stop-opacity:1" />
                <stop offset="100%" style="stop-color:${primary};stop-opacity:1" />
            </linearGradient>
        </defs>
        <rect width="100%" height="100%" fill="url(#grad-${seed.substring(0, 4)})" />
        ${shapes}
    </svg>
    `.replace(/\s+/g, ' ').trim(); // Minify slightly

    return svg;
}

module.exports = { generateAvatarSvg };
