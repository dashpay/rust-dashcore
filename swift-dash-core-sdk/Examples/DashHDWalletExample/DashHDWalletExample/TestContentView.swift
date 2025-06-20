import SwiftUI

struct TestContentView: View {
    var body: some View {
        VStack {
            Text("Dash HD Wallet")
                .font(.largeTitle)
                .padding()
            
            Text("iOS App is running!")
                .font(.title2)
                .foregroundColor(.green)
            
            Spacer()
        }
        .padding()
    }
}