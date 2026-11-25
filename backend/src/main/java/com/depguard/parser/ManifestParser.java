package com.depguard.parser;

import com.depguard.model.DependencyGraph;
import com.depguard.model.Ecosystem;

/**
 * Common contract for ecosystem manifest parsers.
 */
public interface ManifestParser {
    Ecosystem getSupportedEcosystem();
    DependencyGraph parse(String projectName, String manifestContent);
}
