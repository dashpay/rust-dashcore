import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

struct Clipboard {
    static func copy(_ string: String) {
        #if os(iOS)
        UIPasteboard.general.string = string
        #elseif os(macOS)
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(string, forType: .string)
        #endif
    }
    
    static func paste() -> String? {
        #if os(iOS)
        return UIPasteboard.general.string
        #elseif os(macOS)
        return NSPasteboard.general.string(forType: .string)
        #endif
    }
}

struct CopyButton: View {
    let text: String
    let label: String
    @State private var copied = false
    
    init(_ text: String, label: String = "Copy") {
        self.text = text
        self.label = label
    }
    
    var body: some View {
        Button(action: {
            Clipboard.copy(text)
            copied = true
            
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                copied = false
            }
        }) {
            Label(copied ? "Copied!" : label, systemImage: copied ? "checkmark.circle" : "doc.on.doc")
        }
        .foregroundColor(copied ? .green : .accentColor)
        #if os(iOS)
        .buttonStyle(.bordered)
        #endif
    }
}