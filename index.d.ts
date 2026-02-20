declare module 'inslash' {

    // -------------------------------------------------------------------------
    // Option types
    // -------------------------------------------------------------------------

    export type Algorithm = 'sha256' | 'sha384' | 'sha512';
    export type Encoding = 'hex' | 'base64' | 'base64url';
    export type SecurityPreset = 'fast' | 'balanced' | 'strong' | 'paranoid';

    export interface HashOptions {
        saltLength?: number;
        hashLength?: number;
        iterations?: number;
        algorithm?: Algorithm;
        encoding?: Encoding;
        /** Security preset shorthand — overrides individual options if provided. */
        preset?: SecurityPreset;
    }

    export interface ApiKeyOptions {
        prefix?: string;
        /** Number of random bytes to generate (default: 32). */
        byteLength?: number;
        encoding?: Encoding;
    }

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    export interface HistoryEntry {
        date: string;
        algorithm: Algorithm;
        iterations: number;
        encoding?: Encoding;
        event?: string;
        reasons?: string[];
    }

    export interface HashResult {
        passport: string;
        version: string;
        algorithm: Algorithm;
        iterations: number;
        saltLength: number;
        hashLength: number;
        encoding: Encoding;
        salt: string;
        hash: string;
        history: HistoryEntry[];
    }

    export interface VerifyResult {
        valid: boolean;
        needsUpgrade: boolean;
        upgradeReasons: string[];
        upgradedPassport: string | null;
        upgradedMetadata: {
            algorithm: Algorithm;
            iterations: number;
            saltLength: number;
            hashLength: number;
            encoding: Encoding;
        } | null;
        metadata: {
            version: string;
            algorithm: Algorithm;
            iterations: number;
            encoding: Encoding;
            hashLength: number;
            saltLength: number;
        };
    }

    export interface InspectResult {
        valid: boolean;
        version?: string;
        algorithm?: Algorithm;
        iterations?: number;
        saltLength?: number;
        hashLength?: number;
        encoding?: Encoding;
        salt?: string;
        hash?: string;
        history?: HistoryEntry[];
        error?: string;
    }

    export interface CompareResult {
        sameAlgorithm: boolean;
        sameIterations: boolean;
        sameEncoding: boolean;
        sameSalt: boolean;
        sameHash: boolean;
        /** True when both hash AND salt are identical (i.e. same passport). */
        identical: boolean;
        error?: string;
    }

    export interface SecurityEstimate {
        score: number;
        level: 'Excellent' | 'Strong' | 'Good' | 'Fair' | 'Weak' | 'Critical' | 'Invalid';
        recommendations: string[];
        metadata: {
            algorithm: Algorithm;
            iterations: number;
            saltLength: number;
            hashLength: number;
        };
        error?: string;
    }

    export interface BatchVerifyResult {
        value: string;
        valid: boolean;
        needsUpgrade?: boolean;
        error?: string;
    }

    export interface ConfigureOptions {
        apiKey?: string;
        apiUrl?: string;
        strictMode?: boolean;
        timeout?: number;
    }

    // -------------------------------------------------------------------------
    // Core functions
    // -------------------------------------------------------------------------

    export function hash(
        value: string,
        secret: string,
        options?: HashOptions
    ): Promise<HashResult>;

    export function verify(
        value: string,
        passport: string,
        secret: string,
        options?: HashOptions
    ): Promise<VerifyResult>;

    // -------------------------------------------------------------------------
    // Passport utilities
    // -------------------------------------------------------------------------

    export function encodePassport(meta: Record<string, unknown>): string;
    export function decodePassport(passport: string): Record<string, unknown>;
    export function inspectPassport(passport: string): InspectResult;
    export function comparePassports(passport1: string, passport2: string): CompareResult;

    // -------------------------------------------------------------------------
    // Batch operations
    // -------------------------------------------------------------------------

    export function batchVerify(
        values: string[],
        passport: string,
        secret: string,
        options?: HashOptions & { concurrency?: number }
    ): Promise<BatchVerifyResult[]>;

    // -------------------------------------------------------------------------
    // Security analysis
    // -------------------------------------------------------------------------

    export function estimateSecurity(passport: string): SecurityEstimate;

    // -------------------------------------------------------------------------
    // Key utilities
    // -------------------------------------------------------------------------

    export function generateApiKey(options?: ApiKeyOptions): string;

    export function deriveKey(
        password: string,
        salt: string,
        opts?: { iterations?: number; keyLength?: number; algorithm?: Algorithm }
    ): Promise<Buffer>;

    // -------------------------------------------------------------------------
    // API configuration
    // -------------------------------------------------------------------------

    export function configure(options: ConfigureOptions): typeof CONFIG;

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    export const DEFAULTS: {
        saltLength: number;
        hashLength: number;
        iterations: number;
        algorithm: Algorithm;
        encoding: Encoding;
        concurrency: number;
    };

    export const SECURITY_PRESETS: {
        readonly fast: Required<Omit<HashOptions, 'preset'>>;
        readonly balanced: Required<Omit<HashOptions, 'preset'>>;
        readonly strong: Required<Omit<HashOptions, 'preset'>>;
        readonly paranoid: Required<Omit<HashOptions, 'preset'>>;
    };

    export const SUPPORTED_ALGORITHMS: ReadonlyArray<Algorithm>;
    export const SUPPORTED_ENCODINGS: ReadonlyArray<Encoding>;
    export const VERSION: string;

    // Internal (not exported at runtime but useful for typing configure return)
    interface CONFIG {
        apiKey: string | null;
        apiUrl: string | null;
        strictMode: boolean;
        timeout: number;
    }
}