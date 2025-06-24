import SwiftUI
import SwiftDashCoreSDK

struct WatchStatusView: View {
    let status: WatchVerificationStatus
    
    var body: some View {
        HStack {
            switch status {
            case .unknown:
                EmptyView()
            case .verifying:
                ProgressView()
                    .scaleEffect(0.8)
                Text("Verifying watched addresses...")
                    .font(.caption)
                    .foregroundColor(.secondary)
            case .verified(let total, let watching):
                if total == watching {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                    Text("All \(total) addresses watched")
                        .font(.caption)
                } else {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    Text("\(watching)/\(total) addresses watched")
                        .font(.caption)
                }
            case .failed(let error):
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
                Text("Verification failed: \(error)")
                    .font(.caption)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal)
    }
}

struct WatchErrorsView: View {
    let errors: [WatchAddressError]
    let pendingCount: Int
    
    var body: some View {
        if !errors.isEmpty || pendingCount > 0 {
            VStack(alignment: .leading, spacing: 8) {
                if pendingCount > 0 {
                    HStack {
                        Image(systemName: "clock.arrow.circlepath")
                            .foregroundColor(.orange)
                        Text("\(pendingCount) addresses pending retry")
                            .font(.caption)
                    }
                }
                
                ForEach(Array(errors.prefix(3).enumerated()), id: \.offset) { _, error in
                    HStack {
                        Image(systemName: "exclamationmark.circle.fill")
                            .foregroundColor(.red)
                            .font(.caption)
                        Text(error.localizedDescription)
                            .font(.caption)
                            .lineLimit(2)
                    }
                }
                
                if errors.count > 3 {
                    Text("And \(errors.count - 3) more errors...")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding()
            .background(Color.red.opacity(0.1))
            .cornerRadius(8)
        }
    }
}

#Preview {
    VStack(spacing: 20) {
        WatchStatusView(status: .unknown)
        WatchStatusView(status: .verifying)
        WatchStatusView(status: .verified(total: 20, watching: 20))
        WatchStatusView(status: .verified(total: 20, watching: 15))
        WatchStatusView(status: .failed(error: "Network error"))
        
        WatchErrorsView(
            errors: [
                WatchAddressError.networkError("Connection timeout"),
                WatchAddressError.storageFailure("Disk full")
            ],
            pendingCount: 3
        )
    }
    .padding()
}