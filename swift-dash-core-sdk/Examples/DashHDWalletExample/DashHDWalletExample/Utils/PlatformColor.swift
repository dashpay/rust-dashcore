import SwiftUI

#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

struct PlatformColor {
    static var controlBackground: Color {
        #if os(iOS)
        return Color(UIColor.systemGroupedBackground)
        #elseif os(macOS)
        return Color(NSColor.controlBackgroundColor)
        #endif
    }
    
    static var textBackground: Color {
        #if os(iOS)
        return Color(UIColor.secondarySystemGroupedBackground)
        #elseif os(macOS)
        return Color(NSColor.textBackgroundColor)
        #endif
    }
    
    static var secondarySystemBackground: Color {
        #if os(iOS)
        return Color(UIColor.secondarySystemBackground)
        #elseif os(macOS)
        return Color(NSColor.controlBackgroundColor)
        #endif
    }
    
    static var secondaryLabel: Color {
        #if os(iOS)
        return Color(UIColor.secondaryLabel)
        #elseif os(macOS)
        return Color(NSColor.secondaryLabelColor)
        #endif
    }
    
    static var tertiaryLabel: Color {
        #if os(iOS)
        return Color(UIColor.tertiaryLabel)
        #elseif os(macOS)
        return Color(NSColor.tertiaryLabelColor)
        #endif
    }
    
    static var systemRed: Color {
        #if os(iOS)
        return Color(UIColor.systemRed)
        #elseif os(macOS)
        return Color(NSColor.systemRed)
        #endif
    }
    
    static var systemGreen: Color {
        #if os(iOS)
        return Color(UIColor.systemGreen)
        #elseif os(macOS)
        return Color(NSColor.systemGreen)
        #endif
    }
    
    static var systemBlue: Color {
        #if os(iOS)
        return Color(UIColor.systemBlue)
        #elseif os(macOS)
        return Color(NSColor.systemBlue)
        #endif
    }
    
    static var systemOrange: Color {
        #if os(iOS)
        return Color(UIColor.systemOrange)
        #elseif os(macOS)
        return Color(NSColor.systemOrange)
        #endif
    }
    
    static var tertiarySystemBackground: Color {
        #if os(iOS)
        return Color(UIColor.tertiarySystemBackground)
        #elseif os(macOS)
        return Color(NSColor.windowBackgroundColor)
        #endif
    }
}