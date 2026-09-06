import Foundation
import Combine
import SwiftUI

// MARK: - Модели заказов/обращений (lk.fa.ru/services/api/otrs/v2/servicing/service-ticket)

struct ServicesOrdersResponse: Codable {
    let totalCount: Int
    let page: Int
    let pageCount: Int
    let pageSize: Int
    let items: [ServicesOrder]
}

struct ServicesOrder: Codable, Identifiable, Hashable {
    let id: Int
    let createdAt: Int64?
    let title: String?
    let ticket: OrderTicket?
    let service: OrderService?
    let status: String?
    let dynamicFields: [OrderDynamicField]?
    let documentIds: [Int]?
    
    var displayTitle: String {
        title ?? "Обращение #\(ticket?.ticketNumber ?? "?")"
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
    
    var statusTitle: String {
        switch ticket?.state ?? "" {
        case "in_work": return "В работе"
        case "closed": return "Закрыто"
        case "new": return "Новое"
        case "wait": return "Ожидание"
        default: return ticket?.state ?? "—"
        }
    }
    
    var statusColor: Color {
        switch ticket?.stateType ?? "" {
        case "open": return .blue
        case "closed": return .green
        default: return .orange
        }
    }
    
    var serviceName: String {
        service?.title ?? service?.name ?? "Услуга"
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
    
    static func == (lhs: ServicesOrder, rhs: ServicesOrder) -> Bool {
        lhs.id == rhs.id
    }
}

struct OrderTicket: Codable, Hashable {
    let id: Int?
    let ticketNumber: String?
    let state: String?
    let stateType: String?
    let serviceId: Int?
    
    enum CodingKeys: String, CodingKey {
        case id, ticketNumber, state, stateType
        case serviceId = "serviceId"
    }
}

struct OrderService: Codable, Hashable {
    let id: Int?
    let name: String?
    let title: String?
    let type: String?
    let buttonName: String?
}

struct OrderDynamicField: Codable, Hashable {
    let name: String?
    let value: String?
}

// MARK: - Менеджер заказов

@MainActor
final class ServicesOrdersManager: ObservableObject {
    static let shared = ServicesOrdersManager()
    
    @Published var orders: [ServicesOrder] = []
    @Published var isLoading = false
    @Published var error: String? = nil
    @Published var lastUpdated: Date? = nil
    
    private let cacheKey = "cachedServicesOrders"
    private let cacheDateKey = "cachedServicesOrdersDate"
    
    private init() {
        loadCache()
    }
    
    // MARK: - Загрузка
    
    func loadOrders(force: Bool = false) async {
        if isLoading { return }
        if !force, !orders.isEmpty { return }
        
        isLoading = true
        error = nil
        
        let urlStr = "https://lk.fa.ru/services/api/otrs/v2/servicing/service-ticket?page=1&pageSize=20"
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
        request.setValue("https://lk.fa.ru/services/home/orders", forHTTPHeaderField: "Referer")
        request.setValue("Europe/Moscow", forHTTPHeaderField: "X-Timezone-IANA")
        
        print("[Orders] Loading from \(urlStr)")
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let http = response as? HTTPURLResponse
            let status = http?.statusCode ?? 0
            print("[Orders] status=\(status), data=\(data.count) bytes")
            
            guard status == 200 else {
                let bodyPreview = String(data: data, encoding: .utf8)?.prefix(200) ?? "<binary>"
                print("[Orders] error body=\(bodyPreview)")
                self.error = "Ошибка сервера: \(status)"
                self.isLoading = false
                return
            }
            
            let decoded = try JSONDecoder().decode(ServicesOrdersResponse.self, from: data)
            self.orders = decoded.items.sorted { ($0.createdAt ?? 0) > ($1.createdAt ?? 0) }
            self.lastUpdated = Date()
            self.error = nil
            
            // Кэш
            if let json = String(data: data, encoding: .utf8),
               let shared = UserDefaults(suiteName: "group.com.schedule.ruz") {
                shared.set(json, forKey: cacheKey)
                shared.set(Date().timeIntervalSince1970, forKey: cacheDateKey)
            }
        } catch {
            print("[Orders] decode error: \(error.localizedDescription)")
            self.error = "Не удалось разобрать ответ: \(error.localizedDescription)"
        }
        self.isLoading = false
    }
    
    func refreshOrders() async {
        orders = []
        await loadOrders(force: true)
    }
    
    // MARK: - Кэш
    
    private func loadCache() {
        guard let shared = UserDefaults(suiteName: "group.com.schedule.ruz"),
              let json = shared.string(forKey: cacheKey),
              let data = json.data(using: .utf8) else { return }
        
        if let decoded = try? JSONDecoder().decode(ServicesOrdersResponse.self, from: data) {
            self.orders = decoded.items.sorted { ($0.createdAt ?? 0) > ($1.createdAt ?? 0) }
            if let timestamp = shared.object(forKey: cacheDateKey) as? TimeInterval {
                self.lastUpdated = Date(timeIntervalSince1970: timestamp)
            }
        }
    }
}
