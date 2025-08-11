#!/bin/bash

# Script to clean SwiftData/CoreData files from iOS Simulator

echo "Cleaning SwiftData/CoreData files from iOS Simulator..."

# Find all simulator device directories
SIMULATOR_DIR="$HOME/Library/Developer/CoreSimulator/Devices"

if [ -d "$SIMULATOR_DIR" ]; then
    # Find and remove all default.store files and related files
    find "$SIMULATOR_DIR" -name "default.store*" -type f -exec rm -f {} \; 2>/dev/null
    find "$SIMULATOR_DIR" -name "*.store" -type f -exec rm -f {} \; 2>/dev/null
    find "$SIMULATOR_DIR" -name "*.store-shm" -type f -exec rm -f {} \; 2>/dev/null
    find "$SIMULATOR_DIR" -name "*.store-wal" -type f -exec rm -f {} \; 2>/dev/null
    
    # Remove SwiftData directories
    find "$SIMULATOR_DIR" -name "SwiftData" -type d -exec rm -rf {} \; 2>/dev/null
    
    echo "✅ Cleanup completed!"
    echo ""
    echo "Please rebuild and run your app in the simulator."
else
    echo "❌ Simulator directory not found at: $SIMULATOR_DIR"
fi