declare module 'inslash' {
    export interface HashOptions {
        saltLength?: number;
        hashLength?: number;
        iterations?: number;
        algorithm?: 'sha256' | 'sha512' | 'sha384';
        encoding?: 'hex' | 'base64' | 'base64url' | 'latin1';
    }

    export interface HashResult {
        passport: string;
        algorithm: string;
        iterations: number;
        saltLength: number;
        hashLength: number;
        salt: string;
        hash: string;
        encoding: string;
        history: Array<{
            date: string;
            algorithm: string;
            iterations: number;
            encoding?: string;
        }>;
    }

    export interface VerifyResult {
        valid: boolean;
        needsUpgrade: boolean;
        upgradeReasons?: string[];
        upgradedPassport: string | null;
        upgradedMetadata: {
            algorithm: string;
            iterations: number;
            encoding: string;
        } | null;
        metadata: {
            algorithm: string;
            iterations: number;
            encoding: string;
            hashLength: number;
            saltLength: number;
        };
    }

    export interface InspectResult {
        valid: boolean;
        algorithm?: string;
        iterations?: number;
        saltLength?: number;
        hashLength?: number;
        salt?: string;
        hash?: string;
        history?: any[];
        encoding?: string;
        error?: string;
    }

    export interface CompareResult {
        sameAlgorithm: boolean;
        sameIterations: boolean;
        sameSalt: boolean;
        sameHash: boolean;
        sameEncoding: boolean;
        完全相同: boolean;
        error?: string;
    }

    export interface SecurityEstimate {
        score: number;
        level: 'Excellent' | 'Strong' | 'Good' | 'Fair' | 'Weak' | 'Invalid';
        recommendations: string[];
        metadata: {
            algorithm: string;
            iterations: number;
            saltLength: number;
            hashLength: number;
        };
        error?: string;
    }

    export interface ApiKeyOptions {
        prefix?: string;
        length?: number;
        encoding?: 'hex' | 'base64' | 'base64url';
    }

    export function hash(
        value: string,
        secret: string,
        options?: HashOptions
    ): Promise<HashResult>;

    export function verify(
        value: string,
        passport: string,
        secret: string,
        options?: Partial<HashOptions>
    ): Promise<VerifyResult>;

    export function encodePassport(meta: any): string;
    export function decodePassport(passport: string): any;
    
    // New functions
    export function batchVerify(
        values: string[],
        passport: string,
        secret: string,
        options?: Partial<HashOptions>
    ): Promise<Array<{ value: string; valid: boolean; needsUpgrade?: boolean; error?: string }>>;

    export function inspectPassport(passport: string): InspectResult;
    export function comparePassports(passport1: string, passport2: string): CompareResult;
    export function estimateSecurity(passport: string): SecurityEstimate;
    export function generateApiKey(options?: ApiKeyOptions): string;

    // Constants
    export const DEFAULTS: Required<HashOptions>;
    export const SUPPORTED_ALGORITHMS: string[];
    export const SUPPORTED_ENCODINGS: string[];
    export const VERSION: string;
}