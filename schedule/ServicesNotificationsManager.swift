import Foundation
import WebKit

// MARK: - Модели уведомлений (lk.fa.ru/services/api/profile/v1/notification)

struct ServicesNotificationResponse: Codable {
    let totalCount: Int
    let page: Int
    let pageCount: Int
    let pageSize: Int
    let items: [ServicesNotification]
}

struct ServicesNotification: Codable, Identifiable, Hashable {
    let id: Int
    let userId: Int?
    let important: Bool
    let channel: String?
    let message: String?              // Краткий текст
    let seenAt: Int64?                // Unix timestamp
    let createdAt: Int64?             // Unix timestamp
    let data: ServicesNotificationData?
    
    var displayTitle: String {
        data?.title ?? message ?? "Уведомление"
    }
    
    var displayAnnouncement: String {
        data?.announcement ?? ""
    }
    
    var displayHTML: String {
        data?.message ?? message ?? ""
    }
    
    var formattedCreatedAt: String {
        guard let ts = createdAt, ts > 0 else { return "" }
        let date = Date(timeIntervalSince1970: TimeInterval(ts))
        let fmt = DateFormatter()
        fmt.locale = Locale(identifier: "ru_RU")
        fmt.dateStyle = .medium
        fmt.timeStyle = .short
        return fmt.string(from: date)
    }
    
    var isUnread: Bool {
        seenAt == nil
    }
}

struct ServicesNotificationData: Codable {
    let platforms: [String]?
    let message: String?              // HTML-контент (для деталей)
    let title: String?               // "Система расчетов FINPAY"
    let announcement: String?        // Краткий анонс
    let publishFrom: Int64?
    let notificationId: Int?
    
    enum CodingKeys: String, CodingKey {
        case platforms, message, title, announcement, publishFrom
        case notificationId = "notificationId"
    }
}

// MARK: - Менеджер уведомлений

@MainActor
final class ServicesNotificationsManager: ObservableObject {
    static let shared = ServicesNotificationsManager()
    
    @Published var notifications: [ServicesNotification] = []
    @Published var isLoading = false
    @Published var error: String? = nil
    @Published var lastUpdated: Date? = nil
    @Published var unreadCount: Int = 0
    
    private let cacheKey = "cachedNotifications"
    private let cacheDateKey = "cachedNotificationsDate"
    
    private init() {
        loadCache()
    }
    
    // MARK: - Загрузка
    
    func loadNotifications(force: Bool = false) async {
        if isLoading { return }
        if !force, !notifications.isEmpty { return }
        
        isLoading = true
        error = nil
        
        let urlStr = "https://lk.fa.ru/services/api/profile/v1/notification?page=1&pageSize=20"
        guard let url = URL(string: urlStr) else {
            self.error = "Неверный URL"
            self.isLoading = false
            return
        }
        
        // Получаем cookies fa.ru
        let cookies = await LKManager.shared.faCookiesPublic()
        guard !cookies.isEmpty else {
            self.error = "Не авторизован. Войдите в личный кабинет."
            self.isLoading = false
            return
        }
        
        let headerFields = HTTPCookie.requestHeaderFields(with: cookies)
        
        var request = URLRequest(url: url)
        for (name, value) in headerFields {
            request.setValue(value, forHTTPHeaderField: name)
        }
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("https://lk.fa.ru/services/home/notifications", forHTTPHeaderField: "Referer")
        request.setValue("Europe/Moscow", forHTTPHeaderField: "X-Timezone-IANA")
        
        print("[Notifications] Loading from \(urlStr)")
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let http = response as? HTTPURLResponse
            let status = http?.statusCode ?? 0
            print("[Notifications] status=\(status), data=\(data.count) bytes")
            
            guard status == 200 else {
                let bodyPreview = String(data: data, encoding: .utf8)?.prefix(200) ?? "<binary>"
                print("[Notifications] error body=\(bodyPreview)")
                self.error = "Ошибка сервера: \(status)"
                self.isLoading = false
                return
            }
            
            let decoded = try JSONDecoder().decode(ServicesNotificationResponse.self, from: data)
            self.notifications = decoded.items.sorted { ($0.createdAt ?? 0) > ($1.createdAt ?? 0) }
            self.unreadCount = decoded.items.filter { $0.isUnread }.count
            self.lastUpdated = Date()
            self.error = nil
            
            // Кэш
            if let json = String(data: data, encoding: .utf8),
               let shared = UserDefaults(suiteName: "group.com.schedule.ruz") {
                shared.set(json, forKey: cacheKey)
                shared.set(Date().timeIntervalSince1970, forKey: cacheDateKey)
            }
        } catch {
            print("[Notifications] decode error: \(error.localizedDescription)")
            self.error = "Не удалось разобрать ответ: \(error.localizedDescription)"
        }
        self.isLoading = false
    }
    
    func refreshNotifications() async {
        notifications = []
        await loadNotifications(force: true)
    }
    
    // MARK: - Кэш
    
    private func loadCache() {
        guard let shared = UserDefaults(suiteName: "group.com.schedule.ruz"),
              let json = shared.string(forKey: cacheKey),
              let data = json.data(using: .utf8) else { return }
        
        if let decoded = try? JSONDecoder().decode(ServicesNotificationResponse.self, from: data) {
            self.notifications = decoded.items.sorted { ($0.createdAt ?? 0) > ($1.createdAt ?? 0) }
            self.unreadCount = decoded.items.filter { $0.isUnread }.count
            if let timestamp = shared.object(forKey: cacheDateKey) as? TimeInterval {
                self.lastUpdated = Date(timeIntervalSince1970: timestamp)
            }
        }
    }
}
