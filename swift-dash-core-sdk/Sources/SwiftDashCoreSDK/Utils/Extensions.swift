import Foundation

// MARK: - Data Extensions

extension Data {
    /// Convert data to hex string
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }

    /// Create data from hex string
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex

        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }

        self = data
    }
}

// MARK: - String Extensions

extension String {
    /// Validate if string is a valid Dash address
    var isValidDashAddress: Bool {
        // Basic validation - real implementation would use proper address validation
        let mainnetPrefixes = ["X", "7"]
        let testnetPrefixes = ["y", "8", "9"]

        guard count >= 26 && count <= 35 else { return false }

        let firstChar = String(prefix(1))
        return mainnetPrefixes.contains(firstChar) || testnetPrefixes.contains(firstChar)
    }

    /// Shorten string for display (e.g., addresses, txids)
    func shortened(prefix: Int = 6, suffix: Int = 4) -> String {
        guard count > prefix + suffix + 3 else { return self }

        let prefixStr = self.prefix(prefix)
        let suffixStr = self.suffix(suffix)
        return "\(prefixStr)...\(suffixStr)"
    }
}

// MARK: - Numeric Extensions

extension UInt64 {
    /// Convert satoshis to Dash
    var dashValue: Double {
        return Double(self) / 100_000_000.0
    }

    /// Format as Dash string
    var formattedDash: String {
        return String(format: "%.8f DASH", dashValue)
    }
}

extension Double {
    /// Convert Dash to satoshis
    var satoshiValue: UInt64 {
        return UInt64(self * 100_000_000)
    }
}

// MARK: - Date Extensions

extension Date {
    /// Format date for transaction display
    var transactionFormat: String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter.string(from: self)
    }
}

// MARK: - Collection Extensions

extension Collection {
    /// Safe subscript that returns nil instead of crashing
    subscript(safe index: Index) -> Element? {
        return indices.contains(index) ? self[index] : nil
    }
}

// MARK: - Result Extensions

extension Result {
    /// Convert Result to async throwing function
    func get() async throws -> Success {
        switch self {
        case .success(let value):
            return value
        case .failure(let error):
            throw error
        }
    }
}

// MARK: - Task Extensions

extension Task where Success == Never, Failure == Never {
    /// Sleep for a given number of seconds
    static func sleep(seconds: Double) async throws {
        let nanoseconds = UInt64(seconds * 1_000_000_000)
        try await Task.sleep(nanoseconds: nanoseconds)
    }
}