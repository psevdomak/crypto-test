export function cryptoProAdapter(plugin, report) {
    const owned = new Map();

    function run(operation) {
        return new Promise((resolve, reject) => {
            plugin.async_spawn(function* () {
                try {
                    const about = yield plugin.CreateObjectAsync('CAdESCOM.About');
                    const provider = yield about.CSPName(80);
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
        const cspVersion = yield about.CSPVersion(provider, 80);
        return { plugin: yield pluginVersion.toString(), csp: yield cspVersion.toString(), provider };
    }

    function* readers({ info }) {
        const modes = yield info.GetReaderModes();
        const count = yield modes.Count;
        const entries = [];
        for (let i = 0; i < count; i++) {
            const mode = yield modes.ItemByIndex(i);
            entries.push({
                reader: yield mode.Name,
                media: yield mode.Media,
                label: yield mode.NickName,
                flags: yield mode.CarrierFlags,
            });
        }
        return entries;
    }

    function* containers(info) {
        const collection = yield info.EnumContainers();
        const count = yield collection.Count;
        const entries = [];
        for (let i = 0; i < count; i++) {
            const object = yield collection.ItemByIndex(i);
            entries.push({ object, id: yield object.UniqueName });
        }
        return entries;
    }

    function* metadata({ object, id }) {
        return { id, fqcn: yield object.FQCN, reader: yield object.Reader, media: yield object.Media };
    }

    function* createRequest(provider, container, subject, filter) {
        const key = yield plugin.CreateObjectAsync('X509Enrollment.CX509PrivateKey');
        yield key.propset_ProviderName(provider);
        yield key.propset_ContainerName(container);
        yield key.propset_ProviderType(80);
        yield key.propset_ExportPolicy(0);
        yield key.propset_KeySpec(1);
        yield key.propset_Existing(false);

        const request = yield plugin.CreateObjectAsync('X509Enrollment.CX509CertificateRequestPkcs10');
        yield request.InitializeFromPrivateKey(1, key, '');
        const name = yield plugin.CreateObjectAsync('X509Enrollment.CX500DistinguishedName');
        yield name.Encode(subject);
        yield request.propset_Subject(name);
        const usage = yield plugin.CreateObjectAsync('X509Enrollment.CX509ExtensionKeyUsage');
        yield usage.InitializeEncode(32 | 16 | 128 | 64 | 8);
        const identification = yield plugin.CreateObjectAsync('X509Enrollment.CX509ExtensionIdentificationKind');
        yield identification.InitializeEncode(0);
        const extensions = yield request.X509Extensions;
        yield extensions.Add(usage);
        yield extensions.Add(identification);

        const enrollment = yield plugin.CreateObjectAsync('X509Enrollment.CX509Enrollment');
        yield enrollment.InitializeFromRequest(request);
        report('Вызов CreateRequest', { container, filter });
        const csr = yield enrollment.CreateRequest(plugin.XCN_CRYPT_STRING_BASE64);

        let keyId;
        try {
            keyId = yield key.UniqueContainerName;
        } catch (error) {
            report('UniqueContainerName недоступно', error.message || String(error));
        }
        return { csr, keyId };
    }

    function escapePattern(value) {
        return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function readerFormat({ media, flags }) {
        if (/^pkcs11_/i.test(media)) return 'PKCS11';
        if (/^rutoken_fkc_/i.test(media) || (flags & plugin.CARRIER_FLAG_SECURE_MESSAGING)) return 'FKS';
        if (Number.isInteger(flags) && !(flags & plugin.CARRIER_FLAG_FUNCTIONAL_CARRIER)) return 'CSP';
        return undefined;
    }

    function* initialFilter(context, formats) {
        const types = {
            CSP: plugin.ENABLE_CARRIER_TYPE_CSP,
            PKCS11: plugin.ENABLE_CARRIER_TYPE_FKC_NO_SM,
            FKS: plugin.ENABLE_CARRIER_TYPE_FKC_SM,
        };
        const type = formats.reduce((mask, format) => mask | types[format], 0);
        if (formats.length === 1 && !formats.includes('PKCS11')) {
            return { type, regex: '.*', formats };
        }

        const modes = yield* readers(context);
        const media = [...new Set(modes
            .filter((mode) => mode.media && mode.media !== 'NO_MEDIA' && formats.includes(readerFormat(mode)))
            .map((mode) => mode.media))];
        if (!media.length) {
            report('Доступные режимы считывателей', modes);
            throw new Error('Среди подключённых носителей нет выбранных режимов ReaderFilter.');
        }
        return { type, regex: '^(' + media.map(escapePattern).join('|') + ')$', formats, media };
    }

    function* generate(context, name, subject, options = {}) {
        const { about, provider, info } = context;
        const before = new Set((yield* containers(info)).map(({ id }) => id));
        let container = name;
        let filter;
        const { keyFormat, reader, media, readerFormats = [] } = options;
        if (reader) {
            if (reader.includes('\\')) {
                throw new Error('Имя считывателя содержит разделитель полного имени контейнера.');
            }
            const type = keyFormat === 'CSP'
                ? plugin.ENABLE_CARRIER_TYPE_CSP
                : plugin.ENABLE_CARRIER_TYPE_FKC_NO_SM | plugin.ENABLE_CARRIER_TYPE_FKC_SM;
            // ReaderFilter passes the operating-mode pattern to PP_UNIQUE_FILTER.
            filter = { type, regex: '^' + escapePattern(media) + '$', media };
            container = ['\\\\.', reader, name].join('\\');
        } else if (readerFormats.length) {
            filter = yield* initialFilter(context, readerFormats);
        }

        let request;
        if (filter) {
            const operations = plugin.DISABLE_EVERY_CARRIER_OPERATION;
            try {
                yield about.ReaderFilter(filter.type, operations, filter.regex);
                request = yield* createRequest(provider, container, subject, { ...filter, operations });
            } finally {
                yield about.ReaderFilter(plugin.ENABLE_ANY_CARRIER_TYPE, plugin.ENABLE_ANY_OPERATION, '.*');
            }
        } else {
            request = yield* createRequest(provider, container, subject, null);
        }

        const candidates = [];
        for (const entry of yield* containers(info)) {
            if (!entry.id || before.has(entry.id)) {
                continue;
            }
            if (request.keyId) {
                if (entry.id === request.keyId || (yield entry.object.FQCN) === request.keyId) {
                    candidates.push(yield* metadata(entry));
                }
                continue;
            }
            const actualName = yield entry.object.Name;
            const fqcn = yield entry.object.FQCN;
            if ([actualName, fqcn].some(
                (value) => typeof value === 'string' && value.split('\\').at(-1) === name,
            )) {
                candidates.push(yield* metadata(entry));
            }
        }
        if (candidates.length !== 1) {
            report('Идентификация контейнера', { name, keyId: request.keyId, candidates });
            throw new Error('Новый контейнер не определён однозначно. Автоматическое удаление недоступно.');
        }
        const created = candidates[0];
        owned.set(created.id, created);
        report('Создан контейнер', created);
        return { ...created, csr: request.csr };
    }

    function* remove({ info }, expected) {
        const matches = (yield* containers(info)).filter(({ id }) => id === expected.id);
        if (matches.length !== 1) {
            throw new Error('Контейнер для удаления отсутствует или найден неоднозначно.');
        }
        const current = yield* metadata(matches[0]);
        if (!['fqcn', 'reader', 'media'].every((field) => current[field] && current[field] === expected[field])) {
            throw new Error('Метаданные контейнера перед удалением изменились или недоступны.');
        }
        yield matches[0].object.propset_Silent(true);
        yield matches[0].object.Delete();
        if ((yield* containers(info)).some(({ id }) => id === expected.id)) {
            throw new Error('КриптоПро всё ещё видит контейнер после удаления.');
        }
        owned.delete(expected.id);
        report('Удалён контейнер', { id: expected.id });
    }

    return {
        versions: () => run(versions),
        readers: () => run(readers),
        generate: (name, subject, target) => run((context) => generate(context, name, subject, target)),
        remove: ({ id }) => {
            const expected = owned.get(id);
            if (!expected) {
                throw new Error('Контейнер не был создан в этой вкладке.');
            }
            return run((context) => remove(context, expected));
        },
        owned: () => [...owned.values()],
    };
}
