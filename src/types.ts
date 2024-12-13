export interface ProxyRule {
    [key: string]: string;
}

export interface Env {
    ENVIRONMENT: string;
    DOMAIN: string;
}

export interface AuthorizationConfig {
    Realm: string;
    Service: string;
}
