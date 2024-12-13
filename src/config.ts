import { ProxyRule, Env } from './types';

export const enum RegistryURL {
    DockerHub = 'registry-1.docker.io',
    DockerIndex = 'index.docker.io',
    GCR = 'gcr.io',
    Quay = 'quay.io',
    GHCR = 'ghcr.io',
    Stackable = 'docker.stackable.tech',
    K8s = 'registry.k8s.io',
}


const ProxyMappings: { [key: string]: string } = {
    'docker': RegistryURL.DockerHub,
    'docker-index': RegistryURL.DockerIndex,
    'gcr': RegistryURL.GCR,
    'quay': RegistryURL.Quay,
    'ghcr': RegistryURL.GHCR,
    'stackable': RegistryURL.Stackable,
    'k8s': RegistryURL.K8s,
};


export function getProxyRule(env: Env): ProxyRule {
    const domain = env.DOMAIN;

    const defaultProxyRules: ProxyRule = {};

    for (const key in ProxyMappings as { [key: string]: string }) {
        if (ProxyMappings.hasOwnProperty(key)) {
            const url = `${key}.${domain}`;
            defaultProxyRules[url] = ProxyMappings[key];
        }
    }

    if (env.ENVIRONMENT === 'development') {
        defaultProxyRules['localhost'] = ProxyMappings['docker'];
        defaultProxyRules['127.0.0.1'] = ProxyMappings['docker'];
    }

    return defaultProxyRules;
}
