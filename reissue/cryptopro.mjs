import {KeyFormat} from './key-format.mjs';

// Значения совпадают с create-certificate-request-on-token.ts в sme-qds-ui.
const ENABLE_CARRIER_TYPE_CSP = 0x01;
const ENABLE_CARRIER_TYPE_PKCS11 = 0x02;
const ENABLE_ANY_CARRIER_TYPE = 0x07;
const ENABLE_ANY_OPERATION = 0x03;
const DISABLE_EVERY_CARRIER_OPERATION = 0x00;
const MEDIA_TYPE_DEFAULT = 0x00000000;

const NO_MEDIA_FLAG = 'NO_MEDIA';
const NO_UNIQUE_FLAG = 'NO_UNIQUE';
const CRYPTO_PROVIDER_TYPE = 80;

const escapePattern = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Адаптер КриптоПро для стенда. Повторяет поведение sme-qds-ui:
 * - `readers` — как get-reader-modes.ts;
 * - `generate` — как create-certificate-request-on-token.ts;
 * - `remove` — как delete-container-by-unique-name.ts.
 */
export function cryptoProAdapter(plugin, report) {
    // Только для кнопки очистки стенда: сама логика удаления — по id, как в приложении.
    const owned = new Set();

    function run(operation) {
        return new Promise((resolve, reject) => {
            plugin.async_spawn(function* () {
                try {
                    const about = yield plugin.CreateObjectAsync('CAdESCOM.About');
                    const provider = yield about.CSPName(CRYPTO_PROVIDER_TYPE);
                    const info = yield plugin.CreateObjectAsync('X509Enrollment.CCspInformation');
                    yield info.InitializeFromName(provider);
                    resolve(yield* operation({ about, provider, info }));
                } catch (error) {
                    reject(error);
                }
            });
        });
    }

    function* versions({ about, provider }) {
        const pluginVersion = yield about.PluginVersion;
        const cspVersion = yield about.CSPVersion(provider, CRYPTO_PROVIDER_TYPE);
        return {
            plugin: yield pluginVersion.toString(),
            csp: yield cspVersion.toString(),
            provider,
        };
    }

    function* readers({ info }) {
        const modes = yield info.GetReaderModes();
        const count = yield modes.Count;
        const entries = [];
        for (let i = 0; i < count; i++) {
            const mode = yield modes.ItemByIndex(i);
            entries.push({ reader: yield mode.Name, media: yield mode.Media });
        }
        return entries;
    }

    function* containers({ info }) {
        const collection = yield info.EnumContainers();
        const count = yield collection.Count;
        const entries = [];
        for (let i = 0; i < count; i++) {
            const object = yield collection.ItemByIndex(i);
            entries.push({
                object,
                fqcn: yield object.FQCN,
                uniqueName: yield object.UniqueName,
            });
        }
        return entries;
    }

    /** Имя считывателя контейнера — аналог getContainerMetaInfo(containerId).tokenName. */
    function* containerReader(info, containerId, containerName) {
        if (!containerId.trim()) {
            // Пустое имя не найдётся в перечислении контейнеров.
            report('getContainerMetaInfo', 'Empty uniqueContainerName', {
                uniqueContainerName: containerId,
            });
            return undefined;
        }

        try {
            const matches = (yield* containers({ info })).filter(
                ({ fqcn, uniqueName }) =>
                    fqcn === containerId || uniqueName === containerId,
            );
            if (matches.length === 1) return yield matches[0].object.Reader;
            report('getContainerMetaInfo', 'Контейнер не найден однозначно', {
                containerName,
                containerId,
                matches: matches.length,
            });
        } catch (error) {
            report('getContainerMetaInfo', error?.message || String(error), {
                containerName,
                containerId,
            });
        }

        return undefined;
    }

    function* createRequest(provider, containerName, subject) {
        const key = yield plugin.CreateObjectAsync('X509Enrollment.CX509PrivateKey');
        yield key.propset_ProviderName(provider);
        yield key.propset_ContainerName(containerName);
        yield key.propset_Existing(false);
        yield key.propset_ProviderType(CRYPTO_PROVIDER_TYPE);
        yield key.propset_ExportPolicy(0);
        yield key.propset_KeySpec(1);

        const request = yield plugin.CreateObjectAsync(
            'X509Enrollment.CX509CertificateRequestPkcs10',
        );
        yield request.InitializeFromPrivateKey(1, key, '');
        const name = yield plugin.CreateObjectAsync('X509Enrollment.CX500DistinguishedName');
        yield name.Encode(subject);
        yield request.propset_Subject(name);
        const usage = yield plugin.CreateObjectAsync('X509Enrollment.CX509ExtensionKeyUsage');
        yield usage.InitializeEncode(32 | 16 | 128 | 64 | 8);
        const identification = yield plugin.CreateObjectAsync(
            'X509Enrollment.CX509ExtensionIdentificationKind',
        );
        yield identification.InitializeEncode(0);
        const extensions = yield request.X509Extensions;
        yield extensions.Add(usage);
        yield extensions.Add(identification);

        const enrollment = yield plugin.CreateObjectAsync('X509Enrollment.CX509Enrollment');
        yield enrollment.InitializeFromRequest(request);
        const csr = yield enrollment.CreateRequest(plugin.XCN_CRYPT_STRING_BASE64);

        // Закрытый ключ создаётся здесь, поэтому имя контейнера читаем после запроса.
        let containerId = '';
        try {
            containerId = yield key.UniqueContainerName;
        } catch (error) {
            report('createCertificateRequestOnToken:uniqueContainerName', error?.message || String(error), {
                containerName,
            });
        }

        return { csr, containerId };
    }

    function* generate(context, name, subject, target) {
        const { about, provider, info } = context;
        let filterApplied = false;
        let csr;
        let containerId = '';

        try {
            if (target?.reader.includes('\\')) {
                throw new Error(
                    'Имя считывателя содержит разделитель полного имени контейнера.',
                );
            }

            yield about.MediaFilter(plugin.MEDIA_TYPE_SCARD);

            if (target) {
                filterApplied = true;
                yield about.ReaderFilter(
                    target.keyFormat === KeyFormat.Csp
                        ? ENABLE_CARRIER_TYPE_CSP
                        : ENABLE_CARRIER_TYPE_PKCS11,
                    DISABLE_EVERY_CARRIER_OPERATION,
                    '^' + escapePattern(target.media) + '$',
                );
            } else {
                yield about.ReaderFilter(
                    ENABLE_CARRIER_TYPE_PKCS11 | 0x04,
                    ENABLE_ANY_OPERATION,
                    '.*(pkcs11).*',
                );

                const modes = yield info.GetReaderModes();
                const count = yield modes.Count;
                const medias = [];
                for (let i = 0; i < count; i++) {
                    const mode = yield modes.ItemByIndex(i);
                    medias.push(yield mode.Media);
                }

                const hasNoReaders = medias.every(
                    (media) => media === NO_MEDIA_FLAG || media === NO_UNIQUE_FLAG,
                );
                if (hasNoReaders) {
                    yield about.ReaderFilter(
                        ENABLE_CARRIER_TYPE_PKCS11 | 0x04,
                        ENABLE_ANY_OPERATION,
                        '.*.*',
                    );
                }
            }

            const request = yield* createRequest(
                provider,
                target ? ['\\\\.', target.reader, name].join('\\') : name,
                subject,
            );
            csr = request.csr;
            containerId = request.containerId;
        } finally {
            // Узкий фильтр живёт только на время этой генерации.
            if (filterApplied) {
                try {
                    yield about.MediaFilter(MEDIA_TYPE_DEFAULT);
                    yield about.ReaderFilter(
                        ENABLE_ANY_CARRIER_TYPE,
                        ENABLE_ANY_OPERATION,
                        '.*',
                    );
                } catch {
                    // Сброс best-effort: исходный результат не подменяем.
                }
            }
        }

        // Резолв после сброса фильтров — как в create-certificate-request-on-token.ts.
        const reader = yield* containerReader(info, containerId, name);
        owned.add(containerId);

        return {
            payload: {
                certificateRequest: csr,
                certificateRequestMetaInfo: { containerName: name, tokenName: reader },
            },
            containerId,
            reader,
        };
    }

    function* remove({ info }, containerId) {
        const matches = (yield* containers({ info })).filter(
            ({ fqcn, uniqueName }) => fqcn === containerId || uniqueName === containerId,
        );

        if (matches.length !== 1) {
            throw new Error('Контейнер для удаления отсутствует или найден неоднозначно.');
        }

        yield matches[0].object.propset_Silent(true);
        yield matches[0].object.Delete();
        owned.delete(containerId);
    }

    return {
        versions: () => run(versions),
        readers: () => run(readers),
        generate: (name, subject, target) =>
            run((context) => generate(context, name, subject, target)),
        remove: (containerId) => run((context) => remove(context, containerId)),
        owned: () => [...owned],
    };
}
