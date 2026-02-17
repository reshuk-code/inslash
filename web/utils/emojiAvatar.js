// Cute emoji collection for user avatars
const CUTE_EMOJIS = [
    '😊', '😎', '🥳', '🤗', '😸', '🐶', '🐱', '🐼',
    '🦊', '🐨', '🐸', '🦄', '🌈', '⭐', '🌟', '✨',
    '🎨', '🎭', '🎪', '🎯', '🎲', '🎮', '🚀', '💎',
    '🌸', '🌺', '🌻', '🍀', '🌙', '☀️', '🌤️', '🎈'
];

/**
 * Generate a consistent emoji avatar based on a string seed
 * @param {string} seed - Usually username or userId
 * @returns {string} - Emoji character
 */
function generateEmojiAvatar(seed) {
    if (!seed) return '😊'; // default emoji

    // Simple hash function to get consistent index
    let hash = 0;
    for (let i = 0; i < seed.length; i++) {
        const char = seed.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
    }

    // Get absolute value and map to emoji array
    const index = Math.abs(hash) % CUTE_EMOJIS.length;
    return CUTE_EMOJIS[index];
}

module.exports = { generateEmojiAvatar, CUTE_EMOJIS };
