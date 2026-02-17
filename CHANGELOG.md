# Changelog

## [1.1.0] - 2026-02-18

### Added
- 🚀 **Version 2 passport format** with encoding support
- 🔐 **API Key generation** utility (`generateApiKey()`)
- 📊 **Batch verification** for multiple values (`batchVerify()`)
- 🔍 **Passport inspection** without verification (`inspectPassport()`)
- ⚖️ **Passport comparison** utility (`comparePassports()`)
- 📈 **Security strength estimation** (`estimateSecurity()`)
- 🎨 **Multiple encoding support** (hex, base64, base64url, latin1)
- ✅ **Algorithm validation** for supported algorithms
- 📝 **Detailed upgrade reasons** in verify response
- ⏱️ **Timing information** for debugging

### Enhanced
- 🔧 More detailed verification response with metadata
- 📚 Better error messages with suggestions
- 🔄 Backward compatibility with v1 passports
- ⚡ Performance improvements in hashWithSalt

### Fixed
- 🐛 Timing attack protection improvements
- 🔒 Better input validation

## [1.0.3] - 2026-02-16
- Initial release with core functionality