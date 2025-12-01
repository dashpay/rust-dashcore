import SwiftUI
import SwiftData
import SwiftDashCoreSDK

@main
struct DashHDWalletApp: App {
    let modelContainer: ModelContainer

    init() {
        do {
            let schema = Schema([
                HDWallet.self,
                HDAccount.self,
                HDWatchedAddress.self,
                Transaction.self,
                UTXO.self,
                Balance.self,
                SyncState.self
            ])

            let modelConfiguration = ModelConfiguration(
                schema: schema,
                isStoredInMemoryOnly: false,
                groupContainer: .automatic,
                cloudKitDatabase: .none
            )

            modelContainer = try ModelContainer(
                for: schema,
                configurations: [modelConfiguration]
            )
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
                    WalletService.shared.configure(modelContext: modelContainer.mainContext)
                }
        }
    }
}
