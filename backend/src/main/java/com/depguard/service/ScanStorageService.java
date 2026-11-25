package com.depguard.service;

import com.depguard.model.ScanResult;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-Memory Scan Storage and Cache Manager.
 * Stores audit scans safely in-memory without requiring any external database.
 */
public class ScanStorageService {

    private final Map<String, ScanResult> store = new ConcurrentHashMap<>();
    private final List<String> scanOrder = Collections.synchronizedList(new ArrayList<>());

    public void save(ScanResult result) {
        if (result == null || result.getScanId() == null) return;
        store.put(result.getScanId(), result);
        if (!scanOrder.contains(result.getScanId())) {
            scanOrder.add(0, result.getScanId()); // newest first
        }
    }

    public ScanResult get(String scanId) {
        return store.get(scanId);
    }

    public List<ScanResult> getAll() {
        List<ScanResult> list = new ArrayList<>();
        synchronized (scanOrder) {
            for (String id : scanOrder) {
                ScanResult r = store.get(id);
                if (r != null) list.add(r);
            }
        }
        return list;
    }

    public ScanResult getLatest() {
        synchronized (scanOrder) {
            if (!scanOrder.isEmpty()) {
                return store.get(scanOrder.get(0));
            }
        }
        return null;
    }

    public int size() {
        return store.size();
    }
}
