import Foundation

actor AsyncBridge {
    private var progressContinuations: [UUID: AsyncThrowingStream<SyncProgress, Error>.Continuation] = [:]
    private var completionContinuations: [UUID: CheckedContinuation<Void, Error>] = [:]
    private var dataContinuations: [UUID: CheckedContinuation<Data, Error>] = [:]
    
    // MARK: - Progress Stream
    
    func syncProgressStream<T>(
        operation: @escaping (UUID, @escaping (Double, String?) -> Void, @escaping (Bool, String?) -> Void) -> T
    ) -> (T, AsyncThrowingStream<SyncProgress, Error>) {
        let id = UUID()
        
        let stream = AsyncThrowingStream<SyncProgress, Error> { continuation in
            self.addProgressContinuation(id: id, continuation: continuation)
        }
        
        let progressCallback: (Double, String?) -> Void = { [weak self] progress, message in
            Task { [weak self] in
                await self?.handleProgress(id: id, progress: progress, message: message)
            }
        }
        
        let completionCallback: (Bool, String?) -> Void = { [weak self] success, error in
            Task { [weak self] in
                await self?.handleProgressCompletion(id: id, success: success, error: error)
            }
        }
        
        let result = operation(id, progressCallback, completionCallback)
        
        return (result, stream)
    }
    
    // MARK: - Simple Async Operations
    
    func withAsyncCallback(
        operation: @escaping (@escaping (Bool, String?) -> Void) -> Void
    ) async throws {
        let id = UUID()
        
        try await withCheckedThrowingContinuation { continuation in
            Task {
                await self.addCompletionContinuation(id: id, continuation: continuation)
            }
            
            operation { [weak self] success, error in
                Task { [weak self] in
                    await self?.handleCompletion(id: id, success: success, error: error)
                }
            }
        }
    }
    
    func withDataCallback(
        operation: @escaping (@escaping (Data?, String?) -> Void) -> Void
    ) async throws -> Data {
        let id = UUID()
        
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                await self.addDataContinuation(id: id, continuation: continuation)
            }
            
            operation { [weak self] data, error in
                Task { [weak self] in
                    await self?.handleData(id: id, data: data, error: error)
                }
            }
        }
    }
    
    // MARK: - Private Continuation Management
    
    private func addProgressContinuation(id: UUID, continuation: AsyncThrowingStream<SyncProgress, Error>.Continuation) {
        progressContinuations[id] = continuation
    }
    
    private func addCompletionContinuation(id: UUID, continuation: CheckedContinuation<Void, Error>) {
        completionContinuations[id] = continuation
    }
    
    private func addDataContinuation(id: UUID, continuation: CheckedContinuation<Data, Error>) {
        dataContinuations[id] = continuation
    }
    
    // MARK: - Private Handlers
    
    private func handleProgress(id: UUID, progress: Double, message: String?) {
        guard let continuation = progressContinuations[id] else { return }
        
        let syncProgress = SyncProgress(
            currentHeight: 0,
            totalHeight: 0,
            progress: progress,
            status: .scanning,
            message: message
        )
        
        continuation.yield(syncProgress)
    }
    
    private func handleProgressCompletion(id: UUID, success: Bool, error: String?) {
        guard let continuation = progressContinuations.removeValue(forKey: id) else { return }
        
        if success {
            continuation.finish()
        } else {
            let err = DashSDKError.syncError(error ?? "Unknown sync error")
            continuation.finish(throwing: err)
        }
    }
    
    private func handleCompletion(id: UUID, success: Bool, error: String?) {
        guard let continuation = completionContinuations.removeValue(forKey: id) else { return }
        
        if success {
            continuation.resume()
        } else {
            let err = DashSDKError.unknownError(error ?? "Unknown error")
            continuation.resume(throwing: err)
        }
    }
    
    private func handleData(id: UUID, data: Data?, error: String?) {
        guard let continuation = dataContinuations.removeValue(forKey: id) else { return }
        
        if let data = data {
            continuation.resume(returning: data)
        } else {
            let err = DashSDKError.unknownError(error ?? "No data received")
            continuation.resume(throwing: err)
        }
    }
    
    // MARK: - Cleanup
    
    func cancelAll() {
        for (_, continuation) in progressContinuations {
            continuation.finish(throwing: CancellationError())
        }
        progressContinuations.removeAll()
        
        for (_, continuation) in completionContinuations {
            continuation.resume(throwing: CancellationError())
        }
        completionContinuations.removeAll()
        
        for (_, continuation) in dataContinuations {
            continuation.resume(throwing: CancellationError())
        }
        dataContinuations.removeAll()
    }
}