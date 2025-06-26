import Foundation
import DashSPVFFI

// FFI types are imported directly from the C header

internal enum FFIBridge {
    
    // MARK: - String Conversions
    
    static func toString(_ ffiString: FFIString?) -> String? {
        guard let ffiString = ffiString,
              let ptr = ffiString.ptr else {
            return nil
        }
        
        return String(cString: ptr)
    }
    
    static func fromString(_ string: String) -> UnsafePointer<CChar> {
        return (string as NSString).utf8String!
    }
    
    // MARK: - Array Conversions
    
    static func toArray<T>(_ ffiArray: FFIArray?) -> [T]? {
        guard let ffiArray = ffiArray,
              let data = ffiArray.data else {
            return nil
        }
        
        let count = Int(ffiArray.len)
        let buffer = data.bindMemory(to: T.self, capacity: count)
        let array = Array(UnsafeBufferPointer(start: buffer, count: count))
        
        // Note: Caller is responsible for calling dash_spv_ffi_array_destroy
        return array
    }
    
    static func toDataArray(_ ffiArray: FFIArray?) -> [Data]? {
        guard let ffiArray = ffiArray,
              let data = ffiArray.data else {
            return nil
        }
        
        let count = Int(ffiArray.len)
        var result: [Data] = []
        
        for i in 0..<count {
            let ptr = data.advanced(by: i).assumingMemoryBound(to: UnsafeRawPointer.self).pointee
            let len = data.advanced(by: count + i).assumingMemoryBound(to: size_t.self).pointee
            result.append(Data(bytes: ptr, count: len))
        }
        
        // Note: Caller is responsible for calling dash_spv_ffi_array_destroy
        return result
    }
    
    // MARK: - Error Handling
    
    static func checkError(_ code: Int32) throws {
        guard code == 0 else {
            let message = getLastError() ?? "Unknown error"
            throw DashSDKError.ffiError(code: code, message: message)
        }
    }
    
    static func getLastError() -> String? {
        guard let errorPtr = dash_spv_ffi_get_last_error() else {
            return nil
        }
        
        let error = String(cString: errorPtr)
        dash_spv_ffi_clear_error()
        return error
    }
    
    // MARK: - Callback Helpers
    
    // C callbacks that extract the Swift callback from userData
    static let progressCallbackWrapper: @convention(c) (Double, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { progress, message, userData in
        guard let userData = userData else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (Double, String?) -> Void
        let msg = message.map { String(cString: $0) }
        callback(progress, msg)
    }
    
    static let completionCallbackWrapper: @convention(c) (Bool, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { success, error, userData in
        guard let userData = userData else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (Bool, String?) -> Void
        let err = error.map { String(cString: $0) }
        callback(success, err)
    }
    
    static let blockCallbackWrapper: @convention(c) (UInt32, UnsafePointer<CChar>?, UnsafeMutableRawPointer?) -> Void = { height, hash, userData in
        guard let userData = userData, let hash = hash else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (UInt32, String) -> Void
        callback(height, String(cString: hash))
    }
    
    static let transactionCallbackWrapper: @convention(c) (UnsafePointer<CChar>?, Bool, Int64, UnsafePointer<CChar>?, UInt32, UnsafeMutableRawPointer?) -> Void = { txid, confirmed, amount, addresses, blockHeight, userData in
        guard let userData = userData, let txid = txid else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (String, Bool, Int64, [String], UInt32) -> Void
        let txidString = String(cString: txid)
        let addressArray: [String] = {
            if let addresses = addresses {
                let addressesString = String(cString: addresses)
                return addressesString.split(separator: ",").map(String.init)
            }
            return []
        }()
        callback(txidString, confirmed, amount, addressArray, blockHeight)
    }
    
    static let balanceCallbackWrapper: @convention(c) (UInt64, UInt64, UnsafeMutableRawPointer?) -> Void = { confirmed, unconfirmed, userData in
        guard let userData = userData else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (UInt64, UInt64) -> Void
        callback(confirmed, unconfirmed)
    }
    
    // Helper to create userData from callback
    static func createUserData<T: AnyObject>(from object: T) -> UnsafeMutableRawPointer {
        return Unmanaged.passRetained(object).toOpaque()
    }
    
    static func releaseUserData(_ userData: UnsafeMutableRawPointer) {
        Unmanaged<AnyObject>.fromOpaque(userData).release()
    }
    
    // MARK: - Memory Management
    
    static func withCString<T>(_ string: String, _ body: (UnsafePointer<CChar>) throws -> T) rethrows -> T {
        return try string.withCString(body)
    }
    
    static func withOptionalCString<T>(_ string: String?, _ body: (UnsafePointer<CChar>?) throws -> T) rethrows -> T {
        if let string = string {
            return try string.withCString { cString in
                try body(cString)
            }
        } else {
            return try body(nil)
        }
    }
    
    static func withData<T>(_ data: Data, _ body: (UnsafePointer<UInt8>, size_t) throws -> T) rethrows -> T {
        return try data.withUnsafeBytes { bytes in
            let ptr = bytes.bindMemory(to: UInt8.self).baseAddress!
            return try body(ptr, data.count)
        }
    }
    
    // MARK: - Type Conversions
    
    static func convertWatchItemType(_ type: WatchItemType) -> FFIWatchItemType {
        switch type {
        case .address:
            return FFIWatchItemType(rawValue: 0)
        case .script:
            return FFIWatchItemType(rawValue: 1)
        case .outpoint:
            return FFIWatchItemType(rawValue: 2)
        }
    }
    
    static func createFFIWatchItem(type: WatchItemType, data: String) -> FFIWatchItem {
        let cString = (data as NSString).utf8String!
        let length = strlen(cString)
        let ffiString = FFIString(ptr: UnsafeMutablePointer(mutating: cString), length: UInt(length))
        return FFIWatchItem(
            item_type: convertWatchItemType(type),
            data: ffiString
        )
    }
}

// MARK: - Watch Item Type

public enum WatchItemType {
    case address
    case script
    case outpoint
}