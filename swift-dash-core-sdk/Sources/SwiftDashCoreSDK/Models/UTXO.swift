import Foundation
import SwiftData

@Model
public final class UTXO {
    @Attribute(.unique) public var outpoint: String
    public var txid: String
    public var vout: UInt32
    public var address: String
    public var script: Data
    public var value: UInt64
    public var height: UInt32
    public var isSpent: Bool
    public var confirmations: UInt32
    public var isInstantLocked: Bool
    
    public init(
        outpoint: String,
        txid: String,
        vout: UInt32,
        address: String,
        script: Data,
        value: UInt64,
        height: UInt32 = 0,
        isSpent: Bool = false,
        confirmations: UInt32 = 0,
        isInstantLocked: Bool = false
    ) {
        self.outpoint = outpoint
        self.txid = txid
        self.vout = vout
        self.address = address
        self.script = script
        self.value = value
        self.height = height
        self.isSpent = isSpent
        self.confirmations = confirmations
        self.isInstantLocked = isInstantLocked
    }
    
    internal convenience init(ffiUtxo: FFIUtxo) {
        let outpoint = "\(String(cString: ffiUtxo.txid)):\(ffiUtxo.vout)"
        
        self.init(
            outpoint: outpoint,
            txid: String(cString: ffiUtxo.txid),
            vout: ffiUtxo.vout,
            address: String(cString: ffiUtxo.address),
            script: Data(bytes: ffiUtxo.script, count: Int(ffiUtxo.script_len)),
            value: ffiUtxo.value,
            height: ffiUtxo.height,
            isSpent: false,
            confirmations: ffiUtxo.confirmations,
            isInstantLocked: ffiUtxo.is_instant_locked
        )
    }
    
    public var isSpendable: Bool {
        return !isSpent && (confirmations > 0 || isInstantLocked)
    }
    
    public var formattedValue: String {
        let dash = Double(value) / 100_000_000.0
        return String(format: "%.8f DASH", dash)
    }
}

extension UTXO {
    public static func createOutpoint(txid: String, vout: UInt32) -> String {
        return "\(txid):\(vout)"
    }
    
    public func parseOutpoint() -> (txid: String, vout: UInt32)? {
        let components = outpoint.split(separator: ":")
        guard components.count == 2,
              let vout = UInt32(components[1]) else {
            return nil
        }
        return (String(components[0]), vout)
    }
}