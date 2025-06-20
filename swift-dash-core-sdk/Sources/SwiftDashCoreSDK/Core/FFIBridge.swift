import Foundation
import DashSPVFFI

internal enum FFIBridge {
    
    // MARK: - String Conversions
    
    static func toString(_ ffiString: FFIString?) -> String? {
        guard var ffiString = ffiString,
              let ptr = ffiString.data else {
            return nil
        }
        
        let string = String(cString: ptr)
        dash_spv_ffi_string_destroy(&ffiString)
        return string
    }
    
    static func fromString(_ string: String) -> UnsafePointer<CChar> {
        return (string as NSString).utf8String!
    }
    
    // MARK: - Array Conversions
    
    static func toArray<T>(_ ffiArray: FFIArray?) -> [T]? {
        guard var ffiArray = ffiArray,
              let data = ffiArray.data else {
            return nil
        }
        
        let count = Int(ffiArray.len)
        let buffer = data.bindMemory(to: T.self, capacity: count)
        let array = Array(UnsafeBufferPointer(start: buffer, count: count))
        
        dash_spv_ffi_array_destroy(&ffiArray)
        return array
    }
    
    static func toDataArray(_ ffiArray: FFIArray?) -> [Data]? {
        guard var ffiArray = ffiArray,
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
        
        dash_spv_ffi_array_destroy(&ffiArray)
        return result
    }
    
    // MARK: - Error Handling
    
    static func checkError(_ code: FFIErrorCode) throws {
        guard code == 0 else {
            let error = FFIError(code: code)
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
    
    static let transactionCallbackWrapper: @convention(c) (UnsafePointer<CChar>?, Bool, UnsafeMutableRawPointer?) -> Void = { txid, confirmed, userData in
        guard let userData = userData, let txid = txid else { return }
        let callback = Unmanaged<AnyObject>.fromOpaque(userData).takeUnretainedValue() as! (String, Bool) -> Void
        callback(String(cString: txid), confirmed)
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
            return 0
        case .script:
            return 1
        case .outpoint:
            return 2
        }
    }
    
    static func createFFIWatchItem(type: WatchItemType, data: Data) -> FFIWatchItem {
        return withData(data) { ptr, len in
            FFIWatchItem(
                item_type: convertWatchItemType(type),
                data: ptr,
                data_len: len
            )
        }
    }
}

// MARK: - Watch Item Type

internal enum WatchItemType {
    case address
    case script
    case outpoint
}