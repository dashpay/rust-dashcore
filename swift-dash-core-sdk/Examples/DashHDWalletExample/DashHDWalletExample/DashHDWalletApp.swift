import SwiftUI
import SwiftData
import SwiftDashCoreSDK
#if os(iOS)
import UIKit
#endif

@main
struct DashHDWalletApp: App {
    let modelContainer: ModelContainer
    
    init() {
        do {
            modelContainer = try ModelContainerHelper.createContainer()
        } catch {
            fatalError("Could not create ModelContainer: \(error)")
        }
    }
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .modelContainer(modelContainer)
                .environmentObject(WalletService.shared)
                .onAppear {
                    // Ensure WalletService is configured on main thread
                    WalletService.shared.configure(modelContext: modelContainer.mainContext)
                }
        }
        #if os(iOS)
        .windowResizability(.contentSize)
        #endif
    }
}