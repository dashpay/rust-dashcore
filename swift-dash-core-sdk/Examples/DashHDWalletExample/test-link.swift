#!/usr/bin/env swift

// Test script to verify linking with dash_spv_ffi library

import Foundation

// Try to load the library dynamically
if let handle = dlopen("libdash_spv_ffi.a", RTLD_NOW) {
    print("✅ Successfully loaded libdash_spv_ffi.a")
    
    // Try to find a symbol
    if let symbol = dlsym(handle, "dash_spv_ffi_client_new") {
        print("✅ Found symbol: dash_spv_ffi_client_new")
    } else {
        print("❌ Could not find symbol: dash_spv_ffi_client_new")
    }
    
    dlclose(handle)
} else {
    print("❌ Could not load libdash_spv_ffi.a")
    if let error = dlerror() {
        print("Error: \(String(cString: error))")
    }
}

// Also check if the file exists
let fileManager = FileManager.default
let currentPath = fileManager.currentDirectoryPath
let libraryPath = "\(currentPath)/libdash_spv_ffi.a"

if fileManager.fileExists(atPath: libraryPath) {
    print("✅ Library file exists at: \(libraryPath)")
    
    // Get file attributes
    if let attrs = try? fileManager.attributesOfItem(atPath: libraryPath) {
        if let size = attrs[.size] as? Int {
            print("   Size: \(size) bytes")
        }
    }
} else {
    print("❌ Library file not found at: \(libraryPath)")
}