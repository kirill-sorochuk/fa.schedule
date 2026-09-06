import SwiftUI

// MARK: - Мои обращения и заказы (lk.fa.ru/services/home/orders)

struct LKServicesOrdersView: View {
    @StateObject private var manager = ServicesOrdersManager.shared
    @AppStorage("accentColor") private var accentRaw = "faTeal"
    private var accent: Color { AccentColors.color(accentRaw) }
    
    var body: some View {
        SwiftUI.Group {
            if manager.isLoading && manager.orders.isEmpty {
                loadingView
            } else if let error = manager.error {
                errorView(error)
            } else if manager.orders.isEmpty {
                emptyView
            } else {
                ordersList
            }
        }
        .background(Palette.background.ignoresSafeArea())
        .navigationTitle("Мои обращения")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task {
            if manager.orders.isEmpty {
                await manager.loadOrders()
            }
        }
        .refreshable {
            await manager.refreshOrders()
        }
    }
    
    // MARK: - Загрузка / ошибка / пусто
    
    private var loadingView: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView().controlSize(.large)
            Text("Загрузка обращений...")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
        }
    }
    
    private func errorView(_ message: String) -> some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundStyle(.orange.opacity(0.7))
            Text(message)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)
            Button("Повторить") {
                Task { await manager.loadOrders(force: true) }
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
    }
    
    private var emptyView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 48))
                .foregroundStyle(.secondary.opacity(0.5))
            Text("Нет обращений")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Здесь будут отображаться ваши заявки на услуги")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
        }
    }
    
    // MARK: - Список заказов
    
    private var ordersList: some View {
        ScrollView {
            VStack(spacing: 12) {
                ForEach(manager.orders) { order in
                    OrderCard(order: order, accent: accent)
                }
                
                if let updated = manager.lastUpdated {
                    Text("Обновлено: \(updated.formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.top, 8)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
        }
    }
}

// MARK: - Карточка заказа

private struct OrderCard: View {
    let order: ServicesOrder
    let accent: Color
    @State private var showDetails = false
    
    var body: some View {
        Button {
            showDetails = true
        } label: {
            VStack(alignment: .leading, spacing: 12) {
                // Верхняя строка: номер тикета + статус
                HStack(alignment: .top, spacing: 10) {
                    // Левая колонка: иконка услуги
                    ZStack {
                        Circle()
                            .fill(order.statusColor)
                            .frame(width: 36, height: 36)
                        Image(systemName: "doc.badge.gearshape.fill")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(.white)
                    }
                    
                    // Центральная часть: название + сервис
                    VStack(alignment: .leading, spacing: 4) {
                        Text(order.displayTitle)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(2)
                            .multilineTextAlignment(.leading)
                        
                        Text(order.serviceName)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    
                    Spacer()
                    
                    // Правая колонка: статус + дата
                    VStack(alignment: .trailing, spacing: 6) {
                        Text(order.statusTitle)
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(order.statusColor, in: Capsule())
                        
                        if let dateStr = order.formattedCreatedAt, !dateStr.isEmpty {
                            Text(dateStr)
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
                
                // Динамические поля (телефон, тип документа и т.д.)
                if let fields = order.dynamicFields, !fields.isEmpty {
                    Divider()
                        .padding(.vertical, 4)
                    
                    VStack(alignment: .leading, spacing: 6) {
                        ForEach(fields.prefix(3), id: \.name) { field in
                            HStack(spacing: 6) {
                                Image(systemName: "info.circle.fill")
                                    .font(.system(size: 10))
                                    .foregroundStyle(.secondary)
                                Text("\(field.name ?? ""): \(field.value ?? "")")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                        if fields.count > 3 {
                            Text("Ещё полей: \(fields.count - 3)")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                }
            }
            .padding(14)
            .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .sheet(isPresented: $showDetails) {
            OrderDetailView(order: order)
        }
    }
}

// MARK: - Детальный просмотр заказа

private struct OrderDetailView: View {
    let order: ServicesOrder
    @Environment(\.dismiss) private var dismiss
    @AppStorage("accentColor") private var accentRaw = "faTeal"
    private var accent: Color { AccentColors.color(accentRaw) }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Заголовок
                    Text(order.displayTitle)
                        .font(.title2.weight(.bold))
                        .foregroundStyle(.primary)
                    
                    // Мета-информация
                    HStack(spacing: 12) {
                        // Номер тикета
                        Label(order.ticket?.ticketNumber ?? "—", systemImage: "number")
                            .font(.caption)
                            .foregroundStyle(accent)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(accent.opacity(0.15), in: Capsule())
                        
                        // Статус
                        Label(order.statusTitle, systemImage: "checkmark.circle.fill")
                            .font(.caption)
                            .foregroundStyle(order.statusColor)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(order.statusColor.opacity(0.15), in: Capsule())
                        
                        Spacer()
                    }
                    
                    // Сервис
                    HStack(spacing: 8) {
                        Image(systemName: "gearshape.fill")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Услуга")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                            Text(order.serviceName)
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(.primary)
                        }
                        Spacer()
                    }
                    .padding(12)
                    .background(Color(.tertiarySystemFill), in: RoundedRectangle(cornerRadius: 12))
                    
                    Divider()
                    
                    // Дата создания
                    HStack(spacing: 8) {
                        Image(systemName: "calendar")
                            .foregroundStyle(.secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Создано")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                            Text(order.formattedCreatedAt)
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(.primary)
                        }
                        Spacer()
                    }
                    
                    // Динамические поля
                    if let fields = order.dynamicFields, !fields.isEmpty {
                        Section("Детали") {
                            ForEach(fields, id: \.name) { field in
                                HStack(spacing: 8) {
                                    Image(systemName: "text.alignleft")
                                        .foregroundStyle(.secondary)
                                        .frame(width: 24)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(field.name ?? "Поле")
                                            .font(.caption)
                                            .foregroundStyle(.tertiary)
                                        Text(field.value ?? "—")
                                            .font(.subheadline)
                                            .foregroundStyle(.primary)
                                    }
                                    Spacer()
                                }
                                .padding(.vertical, 4)
                            }
                        }
                    }
                    
                    // Документы
                    if let docIds = order.documentIds, !docIds.isEmpty {
                        Section("Документы") {
                            HStack(spacing: 8) {
                                Image(systemName: "doc.fill")
                                    .foregroundStyle(.secondary)
                                Text("Документов: \(docIds.count)")
                                    .font(.subheadline)
                                    .foregroundStyle(.primary)
                                Spacer()
                            }
                        }
                    }
                }
                .padding(20)
            }
            .navigationTitle("Обращение")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Закрыть") { dismiss() }
                        .foregroundStyle(accent)
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
    }
}
