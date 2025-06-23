"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { useScanMutation } from "../hooks/useScanner";
import { ScanPayload, ManualEndpoint } from "../services/scanner.service";
import { FiUpload, FiCheck, FiX, FiZap, FiShield, FiAlertTriangle, FiLock, FiGlobe, FiPlus, FiTrash2, FiChevronDown, FiChevronUp } from "react-icons/fi";

const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;

const METHOD_COLORS: Record<string, { bg: string; text: string; border: string }> = {
    GET: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
    POST: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
    PUT: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
    DELETE: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
    PATCH: { bg: "bg-violet-500/10", text: "text-violet-400", border: "border-violet-500/30" },
};

const INTENSITY_OPTIONS = [
    { level: "LIGHT" as const, icon: <FiZap className="w-5 h-5" />, desc: "Gentle, fewer requests", color: "#22c55e" },
    { level: "MEDIUM" as const, icon: <FiShield className="w-5 h-5" />, desc: "Balanced coverage", color: "#eab308" },
    { level: "AGGRESSIVE" as const, icon: <FiAlertTriangle className="w-5 h-5" />, desc: "Deep & thorough", color: "#ef4444" },
];

type InputMode = "openapi" | "manual";

interface HeaderEntry { key: string; value: string }
interface QueryEntry { key: string; value: string }

interface EndpointFormState {
    method: typeof METHODS[number];
    path: string;
    description: string;
    headers: HeaderEntry[];
    queryParams: QueryEntry[];
    body: string;
    expanded: boolean;
}

const emptyEndpoint = (): EndpointFormState => ({
    method: "GET",
    path: "",
    description: "",
    headers: [],
    queryParams: [],
    body: "",
    expanded: true,
});

export default function ScanForm() {
    const searchParams = useSearchParams();
    const rescanFrom = searchParams.get("rescanFrom");
    const prefillUrl = searchParams.get("targetUrl");
    const prefillIntensity = searchParams.get("intensity") as "LIGHT" | "MEDIUM" | "AGGRESSIVE" | null;
    const projectId = searchParams.get("projectId");

    const [targetUrl, setTargetUrl] = useState(prefillUrl || "http://localhost:4000");
    const [intensity, setIntensity] = useState<"LIGHT" | "MEDIUM" | "AGGRESSIVE">(prefillIntensity || "MEDIUM");
    const [inputMode, setInputMode] = useState<InputMode>("manual");
    const [openApiSpec, setOpenApiSpec] = useState("");
    const [endpoints, setEndpoints] = useState<EndpointFormState[]>([emptyEndpoint()]);
    const [requestsPerSecond, setRequestsPerSecond] = useState<number | "">("");
    const [authType, setAuthType] = useState<"none" | "bearer" | "api_key">("none");
    const [authValue, setAuthValue] = useState("");
    const [authHeaderName, setAuthHeaderName] = useState("X-API-Key");
    const [showDisclaimer, setShowDisclaimer] = useState(true);

    const scanMutation = useScanMutation();

    const hasEndpointSource = inputMode === "openapi" ? !!openApiSpec : endpoints.some(e => e.path.trim());

    const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (ev) => setOpenApiSpec(ev.target?.result as string);
        reader.readAsText(file);
    };

    // Endpoint management
    const addEndpoint = () => {
        setEndpoints(prev => [...prev, emptyEndpoint()]);
    };

    const removeEndpoint = (index: number) => {
        setEndpoints(prev => prev.filter((_, i) => i !== index));
    };

    const updateEndpoint = (index: number, field: keyof EndpointFormState, value: unknown) => {
        setEndpoints(prev => prev.map((ep, i) => i === index ? { ...ep, [field]: value } : ep));
    };

    const toggleExpand = (index: number) => {
        setEndpoints(prev => prev.map((ep, i) => i === index ? { ...ep, expanded: !ep.expanded } : ep));
    };

    // Header management per endpoint
    const addHeader = (epIndex: number) => {
        setEndpoints(prev => prev.map((ep, i) => i === epIndex ? { ...ep, headers: [...ep.headers, { key: "", value: "" }] } : ep));
    };
    const removeHeader = (epIndex: number, headerIndex: number) => {
        setEndpoints(prev => prev.map((ep, i) => i === epIndex ? { ...ep, headers: ep.headers.filter((_, hi) => hi !== headerIndex) } : ep));
    };
    const updateHeader = (epIndex: number, headerIndex: number, field: "key" | "value", val: string) => {
        setEndpoints(prev => prev.map((ep, i) => {
            if (i !== epIndex) return ep;
            const headers = ep.headers.map((h, hi) => hi === headerIndex ? { ...h, [field]: val } : h);
            return { ...ep, headers };
        }));
    };

    // Query param management per endpoint
    const addQueryParam = (epIndex: number) => {
        setEndpoints(prev => prev.map((ep, i) => i === epIndex ? { ...ep, queryParams: [...ep.queryParams, { key: "", value: "" }] } : ep));
    };
    const removeQueryParam = (epIndex: number, paramIndex: number) => {
        setEndpoints(prev => prev.map((ep, i) => i === epIndex ? { ...ep, queryParams: ep.queryParams.filter((_, pi) => pi !== paramIndex) } : ep));
    };
    const updateQueryParam = (epIndex: number, paramIndex: number, field: "key" | "value", val: string) => {
        setEndpoints(prev => prev.map((ep, i) => {
            if (i !== epIndex) return ep;
            const queryParams = ep.queryParams.map((q, qi) => qi === paramIndex ? { ...q, [field]: val } : q);
            return { ...ep, queryParams };
        }));
    };

    const onSubmit = () => {
        const payload: ScanPayload = { targetUrl, intensity };
        if (projectId) payload.projectId = projectId;

        if (inputMode === "openapi") {
            payload.openApiSpec = openApiSpec;
        } else {
            payload.endpoints = endpoints
                .filter(e => e.path.trim())
                .map(e => {
                    const ep: ManualEndpoint = {
                        path: e.path.startsWith("/") ? e.path : `/${e.path}`,
                        method: e.method,
                    };
                    if (e.description.trim()) ep.description = e.description;

                    const headers: Record<string, string> = {};
                    e.headers.forEach(h => { if (h.key.trim() && h.value.trim()) headers[h.key.trim()] = h.value.trim(); });
                    if (Object.keys(headers).length > 0) ep.headers = headers;

                    const queryParams: Record<string, string> = {};
                    e.queryParams.forEach(q => { if (q.key.trim() && q.value.trim()) queryParams[q.key.trim()] = q.value.trim(); });
                    if (Object.keys(queryParams).length > 0) ep.queryParams = queryParams;

                    if (["POST", "PUT", "PATCH"].includes(e.method) && e.body.trim()) {
                        ep.body = e.body.trim();
                    }

                    return ep;
                });
        }

        if (authType !== "none" && authValue) {
            payload.authConfig = { type: authType, value: authValue };
            if (authType === "api_key") payload.authConfig.headerName = authHeaderName;
        }
        if (requestsPerSecond !== "" && !isNaN(Number(requestsPerSecond))) payload.requestsPerSecond = Number(requestsPerSecond);

        scanMutation.mutate(payload);
    };

    const isReady = targetUrl && hasEndpointSource;
    const validEndpointCount = endpoints.filter(e => e.path.trim()).length;

    const inputCls = "w-full bg-[#0D0D0D] border border-[#2D2D2D] rounded-[4px] px-4 py-2.5 text-[#E7E7E7] text-sm font-mono outline-none transition-all focus:border-[#8b5cf6]/50 focus:ring-1 focus:ring-[#8b5cf6]/20 placeholder-[#797979]";
    const smallInputCls = "flex-1 bg-[#0D0D0D] border border-[#2D2D2D] rounded-[4px] px-3 py-2 text-[#E7E7E7] text-[12px] font-mono outline-none transition-all focus:border-[#8b5cf6]/50 placeholder-[#797979]";

    return (
        <div className=" rounded-[4px] overflow-hidden">
            {/* Disclaimer Banner */}
            {showDisclaimer && (
                <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#2D2D2D] bg-red-500/5">
                    <div className="flex items-center gap-2">
                        <FiAlertTriangle className="w-4 h-4 text-red-400" />
                        <span className="text-[12px] text-[#797979]">
                            Only scan APIs you <span className="text-[#E7E7E7]">own or have permission</span> to test
                        </span>
                    </div>
                    <button onClick={() => setShowDisclaimer(false)} className="text-[#797979] hover:text-[#E7E7E7] transition-colors">
                        <FiX className="w-4 h-4" />
                    </button>
                </div>
            )}

            {rescanFrom && (
                <div className="flex items-center gap-2 px-4 py-2.5 border-b border-[#2D2D2D] bg-[#8b5cf6]/5">
                    <span className="text-[11px] font-bold text-[#8b5cf6] uppercase tracking-wider">Rescan</span>
                    <span className="text-[12px] text-[#797979]">Pre-filled from previous scan</span>
                </div>
            )}

            {/* URL Bar */}
            <div className="flex items-center gap-3 p-4 border-b border-[#2D2D2D] bg-[#0a0a0a]">
                <select
                    value={intensity}
                    onChange={(e) => setIntensity(e.target.value as typeof intensity)}
                    className="appearance-none bg-[#1A1A1A] border border-[#2D2D2D] rounded-[4px] px-3 py-2.5 text-[11px] font-bold outline-none cursor-pointer hover:border-[#3D3D3D] transition-colors"
                    style={{ color: INTENSITY_OPTIONS.find(i => i.level === intensity)?.color }}
                >
                    <option value="LIGHT">LIGHT</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="AGGRESSIVE">AGGRESSIVE</option>
                </select>

                <input
                    type="url"
                    className="flex-1 bg-[#0D0D0D] border border-[#2D2D2D] rounded-[4px] px-4 py-2.5 text-[#E7E7E7] text-sm font-mono outline-none transition-all focus:border-[#8b5cf6]/50 focus:ring-1 focus:ring-[#8b5cf6]/20 placeholder-[#797979]"
                    placeholder="http://localhost:4000"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                />

                <button
                    onClick={onSubmit}
                    disabled={!isReady || scanMutation.isPending}
                    className="flex items-center gap-2 px-6 py-2.5 rounded-[4px] text-[13px] font-bold bg-[#8b5cf6] hover:bg-[#7c3aed] disabled:opacity-40 disabled:cursor-not-allowed text-white transition-all"
                >
                    {scanMutation.isPending ? (
                        <>
                            <span className="w-4 h-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                            Scanning…
                        </>
                    ) : (
                        <>Launch Scan</>
                    )}
                </button>
            </div>

            {/* Main Content */}
            <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-[#2D2D2D]">
                {/* Left - Configuration */}
                <div className="lg:col-span-2 p-5 space-y-6">
                    {/* Intensity */}
                    <div>
                        <label className="block text-[11px] font-semibold text-[#797979] uppercase tracking-wider mb-3">
                            Scan Intensity
                        </label>
                        <div className="grid grid-cols-3 gap-3">
                            {INTENSITY_OPTIONS.map(({ level, icon, desc, color }) => (
                                <button
                                    key={level}
                                    onClick={() => setIntensity(level)}
                                    className={`p-4 rounded-[4px] border text-left transition-all ${intensity === level
                                            ? "border-[#8b5cf6]/50 bg-[#8b5cf6]/10"
                                            : "border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#3D3D3D]"
                                        }`}
                                >
                                    <div className="flex items-center gap-2 mb-2" style={{ color }}>
                                        {icon}
                                        <span className="text-[13px] font-bold" style={{ color: intensity === level ? color : "#E7E7E7" }}>
                                            {level.charAt(0) + level.slice(1).toLowerCase()}
                                        </span>
                                    </div>
                                    <p className="text-[11px] text-[#797979]">{desc}</p>
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Rate Limit */}
                    <div>
                        <label className="block text-[11px] font-semibold text-[#797979] uppercase tracking-wider mb-2">
                            Rate Limit <span className="normal-case tracking-normal font-normal text-[#3D3D3D]">(req/sec)</span>
                        </label>
                        <input
                            type="number"
                            className={inputCls}
                            placeholder="Auto (based on intensity)"
                            value={requestsPerSecond}
                            onChange={(e) => setRequestsPerSecond(e.target.value === "" ? "" : Number(e.target.value))}
                        />
                    </div>

                    {/* Input Mode Selection */}
                    <div>
                        <label className="block text-[11px] font-semibold text-[#797979] uppercase tracking-wider mb-3">
                            Endpoint Input Mode
                        </label>
                        <div className="grid grid-cols-2 gap-3">
                            <button
                                onClick={() => setInputMode("openapi")}
                                className={`p-4 rounded-[4px] border text-left transition-all ${inputMode === "openapi"
                                        ? "border-cyan-500/50 bg-cyan-500/10"
                                        : "border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#3D3D3D]"
                                    }`}
                            >
                                <div className="flex items-center gap-2 mb-1">
                                    <FiGlobe className={`w-4 h-4 ${inputMode === "openapi" ? "text-cyan-400" : "text-[#797979]"}`} />
                                    <span className={`text-[13px] font-bold ${inputMode === "openapi" ? "text-cyan-400" : "text-[#E7E7E7]"}`}>
                                        OpenAPI Spec
                                    </span>
                                </div>
                                <p className="text-[11px] text-[#797979]">Upload OpenAPI/Swagger JSON or YAML file</p>
                            </button>
                            <button
                                onClick={() => setInputMode("manual")}
                                className={`p-4 rounded-[4px] border text-left transition-all ${inputMode === "manual"
                                        ? "border-[#8b5cf6]/50 bg-[#8b5cf6]/10"
                                        : "border-[#2D2D2D] bg-[#0a0a0a] hover:border-[#3D3D3D]"
                                    }`}
                            >
                                <div className="flex items-center gap-2 mb-1">
                                    <FiPlus className={`w-4 h-4 ${inputMode === "manual" ? "text-[#8b5cf6]" : "text-[#797979]"}`} />
                                    <span className={`text-[13px] font-bold ${inputMode === "manual" ? "text-[#8b5cf6]" : "text-[#E7E7E7]"}`}>
                                        Manual Endpoints
                                    </span>
                                </div>
                                <p className="text-[11px] text-[#797979]">Define each endpoint with method, headers, and body</p>
                            </button>
                        </div>
                    </div>

                    {/* OpenAPI Upload */}
                    {inputMode === "openapi" && (
                        <div className="border border-[#2D2D2D] rounded-[4px] p-4 bg-[#0a0a0a]">
                            <div className="flex items-center justify-between mb-3">
                                <div className="flex items-center gap-2">
                                    <FiGlobe className="w-4 h-4 text-cyan-400" />
                                    <span className="text-[13px] font-semibold text-[#E7E7E7]">OpenAPI Specification</span>
                                </div>
                                {openApiSpec && <FiCheck className="w-4 h-4 text-green-400" />}
                            </div>
                            <input type="file" accept=".json,.yaml,.yml" onChange={handleFileUpload} className="hidden" id="spec-upload" />
                            <label
                                htmlFor="spec-upload"
                                className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-[4px] border text-[12px] font-medium cursor-pointer transition-all ${openApiSpec
                                        ? "border-green-500/40 bg-green-500/10 text-green-400"
                                        : "border-[#2D2D2D] bg-[#1A1A1A] text-[#797979] hover:text-[#E7E7E7] hover:border-[#3D3D3D]"
                                    }`}
                            >
                                <FiUpload className="w-4 h-4" />
                                {openApiSpec ? "OpenAPI spec loaded " : "Upload OpenAPI / Swagger file"}
                            </label>
                            {openApiSpec && (
                                <button onClick={() => setOpenApiSpec("")} className="mt-2 text-[11px] text-[#797979] hover:text-red-400 transition-colors">
                                    Remove
                                </button>
                            )}
                        </div>
                    )}

                    {/* Manual Endpoints Builder */}
                    {inputMode === "manual" && (
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <label className="text-[11px] font-semibold text-[#797979] uppercase tracking-wider">
                                    Endpoints ({validEndpointCount})
                                </label>
                                <button
                                    onClick={addEndpoint}
                                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-[4px] text-[11px] font-bold text-[#8b5cf6] border border-[#8b5cf6]/30 bg-[#8b5cf6]/5 hover:bg-[#8b5cf6]/15 transition-all"
                                >
                                    <FiPlus className="w-3 h-3" /> Add Endpoint
                                </button>
                            </div>

                            {endpoints.map((ep, epIdx) => {
                                const mc = METHOD_COLORS[ep.method];
                                const hasBody = ["POST", "PUT", "PATCH"].includes(ep.method);

                                return (
                                    <div key={epIdx} className="border border-[#2D2D2D] rounded-[4px] overflow-hidden bg-[#0a0a0a]">
                                        {/* Endpoint Header Row */}
                                        <div className="flex items-center gap-2 p-3 border-b border-[#2D2D2D] bg-[#0D0D0D]">
                                            <select
                                                value={ep.method}
                                                onChange={(e) => updateEndpoint(epIdx, "method", e.target.value)}
                                                className={`appearance-none ${mc.bg} ${mc.text} ${mc.border} border rounded-[4px] px-2.5 py-1.5 text-[11px] font-bold outline-none cursor-pointer transition-colors`}
                                            >
                                                {METHODS.map(m => <option key={m} value={m}>{m}</option>)}
                                            </select>

                                            <input
                                                type="text"
                                                placeholder="/api/users/:id"
                                                value={ep.path}
                                                onChange={(e) => updateEndpoint(epIdx, "path", e.target.value)}
                                                className="flex-1 bg-transparent border-none text-[#E7E7E7] text-[13px] font-mono outline-none placeholder-[#797979]"
                                            />

                                            <button
                                                onClick={() => toggleExpand(epIdx)}
                                                className="p-1.5 rounded text-[#797979] hover:text-[#E7E7E7] transition-colors"
                                                title={ep.expanded ? "Collapse" : "Expand"}
                                            >
                                                {ep.expanded ? <FiChevronUp className="w-4 h-4" /> : <FiChevronDown className="w-4 h-4" />}
                                            </button>

                                            {endpoints.length > 1 && (
                                                <button
                                                    onClick={() => removeEndpoint(epIdx)}
                                                    className="p-1.5 rounded text-[#797979] hover:text-red-400 transition-colors"
                                                    title="Remove endpoint"
                                                >
                                                    <FiTrash2 className="w-3.5 h-3.5" />
                                                </button>
                                            )}
                                        </div>

                                        {/* Expanded Config */}
                                        {ep.expanded && (
                                            <div className="p-4 space-y-4">
                                                {/* Description */}
                                                <div>
                                                    <label className="block text-[10px] font-semibold text-[#3D3D3D] uppercase tracking-wider mb-1.5">
                                                        Description <span className="normal-case tracking-normal font-normal">(optional)</span>
                                                    </label>
                                                    <input
                                                        type="text"
                                                        placeholder="e.g. Fetch user profile by ID"
                                                        value={ep.description}
                                                        onChange={(e) => updateEndpoint(epIdx, "description", e.target.value)}
                                                        className={smallInputCls}
                                                    />
                                                </div>

                                                {/* Headers */}
                                                <div>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <label className="text-[10px] font-semibold text-[#3D3D3D] uppercase tracking-wider">
                                                            Headers ({ep.headers.length})
                                                        </label>
                                                        <button
                                                            onClick={() => addHeader(epIdx)}
                                                            className="text-[10px] font-bold text-[#8b5cf6] hover:text-[#a78bfa] transition-colors"
                                                        >
                                                            + Add
                                                        </button>
                                                    </div>
                                                    {ep.headers.length > 0 && (
                                                        <div className="space-y-1.5">
                                                            {ep.headers.map((h, hIdx) => (
                                                                <div key={hIdx} className="flex items-center gap-2">
                                                                    <input
                                                                        type="text"
                                                                        placeholder="Header Name"
                                                                        value={h.key}
                                                                        onChange={(e) => updateHeader(epIdx, hIdx, "key", e.target.value)}
                                                                        className={smallInputCls}
                                                                    />
                                                                    <span className="text-[#3D3D3D] text-sm">:</span>
                                                                    <input
                                                                        type="text"
                                                                        placeholder="Header Value"
                                                                        value={h.value}
                                                                        onChange={(e) => updateHeader(epIdx, hIdx, "value", e.target.value)}
                                                                        className={smallInputCls}
                                                                    />
                                                                    <button onClick={() => removeHeader(epIdx, hIdx)} className="text-[#797979] hover:text-red-400 transition-colors shrink-0">
                                                                        <FiX className="w-3.5 h-3.5" />
                                                                    </button>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>

                                                {/* Query Params */}
                                                <div>
                                                    <div className="flex items-center justify-between mb-2">
                                                        <label className="text-[10px] font-semibold text-[#3D3D3D] uppercase tracking-wider">
                                                            Query Params ({ep.queryParams.length})
                                                        </label>
                                                        <button
                                                            onClick={() => addQueryParam(epIdx)}
                                                            className="text-[10px] font-bold text-[#8b5cf6] hover:text-[#a78bfa] transition-colors"
                                                        >
                                                            + Add
                                                        </button>
                                                    </div>
                                                    {ep.queryParams.length > 0 && (
                                                        <div className="space-y-1.5">
                                                            {ep.queryParams.map((q, qIdx) => (
                                                                <div key={qIdx} className="flex items-center gap-2">
                                                                    <input
                                                                        type="text"
                                                                        placeholder="Param Name"
                                                                        value={q.key}
                                                                        onChange={(e) => updateQueryParam(epIdx, qIdx, "key", e.target.value)}
                                                                        className={smallInputCls}
                                                                    />
                                                                    <span className="text-[#3D3D3D] text-sm">=</span>
                                                                    <input
                                                                        type="text"
                                                                        placeholder="Param Value"
                                                                        value={q.value}
                                                                        onChange={(e) => updateQueryParam(epIdx, qIdx, "value", e.target.value)}
                                                                        className={smallInputCls}
                                                                    />
                                                                    <button onClick={() => removeQueryParam(epIdx, qIdx)} className="text-[#797979] hover:text-red-400 transition-colors shrink-0">
                                                                        <FiX className="w-3.5 h-3.5" />
                                                                    </button>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>

                                                {/* Request Body */}
                                                {hasBody && (
                                                    <div>
                                                        <label className="block text-[10px] font-semibold text-[#3D3D3D] uppercase tracking-wider mb-1.5">
                                                            Request Body <span className="normal-case tracking-normal font-normal">(JSON)</span>
                                                        </label>
                                                        <textarea
                                                            className={`${inputCls} resize-none`}
                                                            placeholder={'{\n  "name": "John Doe",\n  "email": "john@example.com"\n}'}
                                                            rows={4}
                                                            value={ep.body}
                                                            onChange={(e) => updateEndpoint(epIdx, "body", e.target.value)}
                                                        />
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* Authentication */}
                    <div>
                        <label className="block text-[11px] font-semibold text-[#797979] uppercase tracking-wider mb-3">
                            Authentication
                        </label>
                        <div className="border border-[#2D2D2D] rounded-[4px] p-4 bg-[#0a0a0a]">
                            <select
                                className="w-full bg-[#1A1A1A] border border-[#2D2D2D] rounded-[4px] px-4 py-2.5 text-[#E7E7E7] text-sm outline-none transition-all focus:border-[#8b5cf6]/50 mb-3"
                                value={authType}
                                onChange={(e) => setAuthType(e.target.value as typeof authType)}
                            >
                                <option value="none">No Authentication</option>
                                <option value="bearer">Bearer Token</option>
                                <option value="api_key">API Key</option>
                            </select>

                            {authType !== "none" && (
                                <div className="mt-3 space-y-3">
                                    <div className="flex items-center gap-2 mb-2">
                                        <FiLock className="w-4 h-4 text-[#8b5cf6]" />
                                        <span className="text-[12px] text-[#797979]">
                                            {authType === "bearer" ? "Bearer Token" : "API Key"}
                                        </span>
                                    </div>

                                    {authType === "api_key" && (
                                        <input
                                            type="text"
                                            className={inputCls}
                                            placeholder="Header name (e.g. X-API-Key)"
                                            value={authHeaderName}
                                            onChange={(e) => setAuthHeaderName(e.target.value)}
                                        />
                                    )}

                                    <input
                                        type="text"
                                        className={inputCls}
                                        placeholder={authType === "bearer" ? "eyJhbGciOiJIUzI1NiIs..." : "your-api-key"}
                                        value={authValue}
                                        onChange={(e) => setAuthValue(e.target.value)}
                                    />
                                    {authValue && (
                                        <div className="flex items-center gap-1.5">
                                            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                                            <span className="text-[11px] text-green-400">Token configured</span>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right - Summary */}
                <div className="bg-[#0a0a0a] p-5">
                    <h3 className="text-[11px] font-semibold text-[#797979] uppercase tracking-wider mb-4">Scan Summary</h3>

                    <div className="space-y-4">
                        {/* Config Summary */}
                        <div className="border border-[#2D2D2D] rounded-[4px] overflow-hidden">
                            <div className="px-3 py-2 bg-[#1A1A1A] border-b border-[#2D2D2D]">
                                <span className="text-[10px] font-bold text-[#797979] uppercase tracking-wider">Configuration</span>
                            </div>
                            <div className="divide-y divide-[#2D2D2D]">
                                {[
                                    { label: "Target", value: targetUrl ? targetUrl.replace(/^https?:\/\//, "") : "—" },
                                    { label: "Intensity", value: intensity },
                                    { label: "Rate", value: requestsPerSecond ? `${requestsPerSecond} req/s` : "Auto" },
                                    { label: "Mode", value: inputMode === "openapi" ? "OpenAPI Spec" : "Manual" },
                                    ...(inputMode === "manual" ? [{ label: "Endpoints", value: `${validEndpointCount} defined` }] : []),
                                ].map(({ label, value }) => (
                                    <div key={label} className="flex justify-between items-center px-3 py-2.5">
                                        <span className="text-[11px] text-[#797979]">{label}</span>
                                        <span className="text-[11px] text-[#E7E7E7] font-mono truncate max-w-[60%] text-right">{value}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Endpoint Preview (Manual Mode) */}
                        {inputMode === "manual" && validEndpointCount > 0 && (
                            <div className="border border-[#2D2D2D] rounded-[4px] overflow-hidden">
                                <div className="px-3 py-2 bg-[#1A1A1A] border-b border-[#2D2D2D]">
                                    <span className="text-[10px] font-bold text-[#797979] uppercase tracking-wider">Endpoints Preview</span>
                                </div>
                                <div className="divide-y divide-[#2D2D2D] max-h-[200px] overflow-y-auto">
                                    {endpoints.filter(e => e.path.trim()).map((ep, i) => {
                                        const mc = METHOD_COLORS[ep.method];
                                        return (
                                            <div key={i} className="flex items-center gap-2 px-3 py-2">
                                                <span className={`text-[10px] font-bold ${mc.text}`}>{ep.method}</span>
                                                <span className="text-[11px] text-[#E7E7E7] font-mono truncate">{ep.path}</span>
                                                {ep.headers.length > 0 && <span className="text-[9px] text-[#3D3D3D]">H:{ep.headers.length}</span>}
                                                {ep.body && <span className="text-[9px] text-[#3D3D3D]">B</span>}
                                                {ep.queryParams.length > 0 && <span className="text-[9px] text-[#3D3D3D]">Q:{ep.queryParams.length}</span>}
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        )}

                        {/* Readiness */}
                        <div className="border border-[#2D2D2D] rounded-[4px] overflow-hidden">
                            <div className="px-3 py-2 bg-[#1A1A1A] border-b border-[#2D2D2D]">
                                <span className="text-[10px] font-bold text-[#797979] uppercase tracking-wider">Readiness</span>
                            </div>
                            <div className="divide-y divide-[#2D2D2D]">
                                {[
                                    { label: "Target URL", ok: !!targetUrl },
                                    { label: "Endpoint source", ok: !!hasEndpointSource },
                                    { label: "Auth configured", ok: authType === "none" || !!authValue, optional: true },
                                ].map(({ label, ok, optional }) => (
                                    <div key={label} className="flex justify-between items-center px-3 py-2.5">
                                        <span className="text-[11px] text-[#797979]">{label}</span>
                                        <span className={`text-[11px] font-bold ${ok ? "text-green-400" : optional ? "text-[#3D3D3D]" : "text-red-400"}`}>
                                            {ok ? "" : optional ? "—" : ""}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Error */}
                        {scanMutation.isError && (
                            <div className="flex items-start gap-2 bg-red-500/5 border border-red-500/20 rounded-[4px] px-3 py-2.5">
                                <FiX className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                                <span className="text-[11px] text-red-400">
                                    {(scanMutation.error as { response?: { data?: { error?: string } } })?.response?.data?.error || "Scan failed. Please try again."}
                                </span>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
