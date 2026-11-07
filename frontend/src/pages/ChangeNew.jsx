import { useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { changes as changesApi, configs as configsApi } from "../api/api.js";
import { useAuth } from "../auth/AuthProvider.jsx";
import { can } from "../auth/permissions.js";
import { ErrorNote, Field, Loading, PageHead, Panel } from "../components/ui.jsx";
import { useResource } from "../hooks/useResource.js";
import { interfaceNames, Violations } from "./configParts.jsx";

/* The JSON schema type of a property; Optional[x] arrives as anyOf [x, null]. */
function kindOf(prop) {
  const type = prop.type ?? prop.anyOf?.find((t) => t.type !== "null")?.type;
  if (type === "array") return "list";
  return type ?? "string";
}

function initialValues(schema) {
  const values = {};
  for (const [name, prop] of Object.entries(schema.properties ?? {})) {
    const def = prop.default;
    values[name] = kindOf(prop) === "list" ? (def ?? []).join("\n") : def ?? (kindOf(prop) === "boolean" ? false : "");
  }
  return values;
}

/* Turn form strings into the types the template expects; the server validates again. */
function toVariables(schema, values) {
  const out = {};
  for (const [name, prop] of Object.entries(schema.properties ?? {})) {
    const value = values[name];
    const kind = kindOf(prop);
    if (kind === "boolean") out[name] = Boolean(value);
    else if (kind === "list") out[name] = String(value).split("\n").map((s) => s.trim()).filter(Boolean);
    else if (value === "" || value === null) continue;
    else if (kind === "integer") out[name] = Number(value);
    else out[name] = String(value);
  }
  return out;
}

const ACRONYMS = /\b(Ip|Id|Vlan|Svi|Ssh|Snmp|Mgmt|Dns|Ntp)\b/g;

/* "Vlan Id" (Pydantic's title for vlan_id) reads better as "VLAN ID". */
function label(name, prop) {
  return (prop.title ?? name.replace(/_/g, " ")).replace(ACRONYMS, (w) => w.toUpperCase());
}

/* A form built from the template's JSON schema (the same Pydantic model the server uses). */
function SchemaForm({ schema, values, onChange }) {
  const required = new Set(schema.required ?? []);
  return Object.entries(schema.properties ?? {}).map(([name, prop]) => {
    const kind = kindOf(prop);
    const set = (value) => onChange({ ...values, [name]: value });
    const hint = [prop.description, kind === "list" ? "One per line." : null].filter(Boolean).join(" ");
    if (kind === "boolean") {
      return (
        <label key={name} className="checkbox">
          <input type="checkbox" checked={Boolean(values[name])} onChange={(e) => set(e.target.checked)} />{" "}
          {label(name, prop)}
        </label>
      );
    }
    return (
      <Field key={name} label={`${label(name, prop)}${required.has(name) ? "" : " (optional)"}`} hint={hint || undefined}>
        {kind === "list" ? (
          <textarea rows={3} value={values[name]} onChange={(e) => set(e.target.value)} />
        ) : (
          <input
            type={kind === "integer" ? "number" : "text"}
            min={prop.minimum}
            max={prop.maximum}
            maxLength={prop.maxLength ?? 120}
            required={required.has(name)}
            value={values[name]}
            onChange={(e) => set(e.target.value)}
          />
        )}
      </Field>
    );
  });
}

export default function ChangeNew() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const preset = useLocation().state ?? {};
  const devices = useResource((signal) => configsApi.overview({ signal }), []);
  const templates = useResource((signal) => changesApi.templates({ signal }), []);
  const [deviceId, setDeviceId] = useState(preset.deviceId ?? "");
  const [mode, setMode] = useState(preset.commands ? "raw" : "template");
  const [templateId, setTemplateId] = useState(preset.template ?? "");
  const [values, setValues] = useState(null);
  const [commands, setCommands] = useState(preset.commands ?? "");
  const [title, setTitle] = useState(preset.title ?? "");
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const changeable = (devices.data ?? []).filter((d) => d.config_vendor);
  const device = changeable.find((d) => d.id === deviceId);
  const available = (templates.data ?? []).filter((t) => t.vendor === device?.config_vendor);
  const template = available.find((t) => t.id === templateId);
  const formValues = useMemo(() => values ?? (template ? initialValues(template.schema) : {}), [values, template]);

  if (!can(user, "change.write")) {
    return <ErrorNote>Only engineers and admins can create changes.</ErrorNote>;
  }

  function source() {
    const body = { device_id: deviceId };
    if (mode === "template") return { ...body, template: templateId, variables: toVariables(template.schema, formValues) };
    return { ...body, commands };
  }

  async function run(fn) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      setError(err);
      if (err.body?.violations) setPreview({ violations: err.body.violations, commands: null });
    } finally {
      setBusy(false);
    }
  }

  const ready = device && (mode === "raw" ? commands.trim() : template);

  return (
    <>
      <PageHead title="New change request" />
      <ErrorNote error={devices.error || templates.error} />
      {(devices.loading || templates.loading) && !devices.data && <Loading />}
      {devices.data && templates.data && (
        <Panel>
          <form
            className="form-grid change-form"
            onSubmit={(e) => {
              e.preventDefault();
              run(async () => {
                const created = await changesApi.create({ title, ...source() });
                navigate(`/changes/${created.id}`);
              });
            }}
          >
            <Field label="Device" hint="Only devices with a config backup can be changed.">
              <select
                required
                value={deviceId}
                onChange={(e) => {
                  setDeviceId(e.target.value);
                  setTemplateId("");
                  setValues(null);
                  setPreview(null);
                }}
              >
                <option value="">Choose a device…</option>
                {changeable.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.sys_name || d.mgmt_ip} ({d.mgmt_ip})
                  </option>
                ))}
              </select>
            </Field>
            <fieldset className="segmented">
              <legend>What to push</legend>
              <label>
                <input type="radio" name="mode" checked={mode === "template"} onChange={() => setMode("template")} />{" "}
                From a template
              </label>
              <label>
                <input type="radio" name="mode" checked={mode === "raw"} onChange={() => setMode("raw")} /> My own
                commands
              </label>
            </fieldset>
            {mode === "template" && (
              <>
                <Field label="Template">
                  <select
                    required
                    value={templateId}
                    onChange={(e) => {
                      setTemplateId(e.target.value);
                      setValues(null);
                      setPreview(null);
                    }}
                    disabled={!device}
                  >
                    <option value="">{device ? "Choose a template…" : "Choose a device first"}</option>
                    {available.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.title}
                      </option>
                    ))}
                  </select>
                </Field>
                {template && <p className="small muted">{template.description}</p>}
                {template && <SchemaForm schema={template.schema} values={formValues} onChange={setValues} />}
              </>
            )}
            {mode === "raw" && (
              <Field
                label="Commands"
                hint="Configuration-mode lines. Indent interface commands under their interface line. No passwords: they would be stored."
              >
                <textarea
                  className="code-input"
                  rows={10}
                  maxLength={20000}
                  spellCheck={false}
                  value={commands}
                  onChange={(e) => {
                    setCommands(e.target.value);
                    setPreview(null);
                  }}
                />
              </Field>
            )}
            <Field label="Title">
              <input required minLength={3} maxLength={120} value={title} onChange={(e) => setTitle(e.target.value)} />
            </Field>
            <div className="form-actions">
              <button
                type="button"
                className="button button-secondary"
                disabled={!ready || busy}
                onClick={() => run(async () => setPreview(await changesApi.preview(source())))}
              >
                Preview (dry run)
              </button>
              <button type="submit" className="button" disabled={!ready || busy || !title.trim()}>
                Save as draft
              </button>
            </div>
          </form>
          <ErrorNote error={error} />
          {preview && (
            <div className="preview">
              <Violations items={preview.violations} />
              {preview.commands && (
                <>
                  <h3>Exactly what the agent will push</h3>
                  <pre className="device-text config-text">{preview.commands}</pre>
                  {preview.violations.length === 0 && (
                    <p className="notice notice-ok">Passed the denylist check.</p>
                  )}
                  {preview.protected_interfaces?.length > 0 && (
                    <p className="small muted">
                      Protected (management and uplink) interfaces: {interfaceNames(preview.protected_interfaces)}
                    </p>
                  )}
                </>
              )}
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
