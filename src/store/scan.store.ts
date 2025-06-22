import { create } from "zustand";
import { ScanProgress } from "@/types";

interface ScanState {
    activeScan: ScanProgress | null;
    scanHistory: string[];
    setActiveScan: (scan: ScanProgress | null) => void;
    updateProgress: (progress: Partial<ScanProgress>) => void;
    addToHistory: (scanId: string) => void;
    clearActiveScan: () => void;
}

export const useScanStore = create<ScanState>((set) => ({
    activeScan: null,
    scanHistory: [],
    setActiveScan: (scan) => set({ activeScan: scan }),
    updateProgress: (progress) =>
        set((state) => ({
            activeScan: state.activeScan
                ? { ...state.activeScan, ...progress }
                : null,
        })),
    addToHistory: (scanId) =>
        set((state) => ({
            scanHistory: [scanId, ...state.scanHistory].slice(0, 50),
        })),
    clearActiveScan: () => set({ activeScan: null }),
}));

interface UIState {
    sidebarOpen: boolean;
    selectedSeverityFilter: string | null;
    toggleSidebar: () => void;
    setSeverityFilter: (filter: string | null) => void;
}

export const useUIStore = create<UIState>((set) => ({
    sidebarOpen: true,
    selectedSeverityFilter: null,
    toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
    setSeverityFilter: (filter) => set({ selectedSeverityFilter: filter }),
}));
