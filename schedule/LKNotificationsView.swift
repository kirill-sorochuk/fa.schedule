import SwiftUI
import WebKit

// MARK: - Уведомления (новый стиль iOS)

struct LKNotificationsView: View {
    @StateObject private var manager = ServicesNotificationsManager.shared
    @AppStorage("accentColor") private var accentRaw = "faTeal"
    private var accent: Color { AccentColors.color(accentRaw) }
    
    var body: some View {
        Group {
            if manager.isLoading && manager.notifications.isEmpty {
                loadingView
            } else if let error = manager.error {
                errorView(error)
            } else if manager.notifications.isEmpty {
                emptyView
            } else {
                notificationsList
            }
        }
        .background(Palette.background.ignoresSafeArea())
        .navigationTitle("Уведомления")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .task {
            if manager.notifications.isEmpty {
                await manager.loadNotifications()
            }
        }
        .refreshable {
            await manager.refreshNotifications()
        }
    }
    
    // MARK: - Загрузка / ошибка / пусто
    
    private var loadingView: some View {
        VStack(spacing: 16) {
            Spacer()
            ProgressView().controlSize(.large)
            Text("Загрузка уведомлений...")
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
                Task { await manager.loadNotifications(force: true) }
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
    }
    
    private var emptyView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "bell.slash")
                .font(.system(size: 48))
                .foregroundStyle(.secondary.opacity(0.5))
            Text("Нет уведомлений")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Здесь будут отображаться важные уведомления из личного кабинета")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 40)
            Spacer()
        }
    }
    
    // MARK: - Список уведомлений
    
    private var notificationsList: some View {
        ScrollView {
            VStack(spacing: 12) {
                ForEach(manager.notifications) { notification in
                    NotificationCard(notification: notification, accent: accent)
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

// MARK: - Карточка уведомления

private struct NotificationCard: View {
    let notification: ServicesNotification
    let accent: Color
    @State private var showDetail = false
    
    var body: some View {
        Button {
            showDetail = true
        } label: {
            VStack(alignment: .leading, spacing: 10) {
                // Верхняя строка: иконка важности + заголовок + дата
                HStack(alignment: .top, spacing: 10) {
                    // Индикатор важности / непрочитанное
                    ZStack {
                        Circle()
                            .fill(notification.important ? accent : Color.blue.opacity(0.3))
                            .frame(width: 32, height: 32)
                        Image(systemName: notification.important ? "exclamationmark.bubble.fill" : "bell.fill")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(.white)
                    }
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text(notification.displayTitle)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.primary)
                            .lineLimit(2)
                            .multilineTextAlignment(.leading)
                        
                        if !notification.displayAnnouncement.isEmpty {
                            Text(notification.displayAnnouncement)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                                .multilineTextAlignment(.leading)
                        }
                    }
                    
                    Spacer()
                    
                    // Дата
                    VStack(alignment: .trailing, spacing: 4) {
                        if notification.isUnread {
                            Circle()
                                .fill(accent)
                                .frame(width: 8, height: 8)
                        }
                        Text(notification.formattedCreatedAt)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            .padding(14)
            .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 16))
            .overlay(
                RoundedRectangle(cornerRadius: 16)
                    .strokeBorder(notification.isUnread ? accent.opacity(0.4) : Color.clear, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
        .sheet(isPresented: $showDetail) {
            NotificationDetailView(notification: notification)
        }
    }
}

// MARK: - Детальный просмотр уведомления

private struct NotificationDetailView: View {
    let notification: ServicesNotification
    @Environment(\.dismiss) private var dismiss
    @AppStorage("accentColor") private var accentRaw = "faTeal"
    private var accent: Color { AccentColors.color(accentRaw) }
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Заголовок
                    Text(notification.displayTitle)
                        .font(.title2.weight(.bold))
                        .foregroundStyle(.primary)
                    
                    // Мета-информация
                    HStack(spacing: 12) {
                        if notification.important {
                            Label("Важное", systemImage: "exclamationmark.shield.fill")
                                .font(.caption)
                                .foregroundStyle(accent)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 6)
                                .background(accent.opacity(0.15), in: Capsule())
                        }
                        
                        Text(notification.formattedCreatedAt)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        
                        Spacer()
                    }
                    
                    Divider()
                    
                    // HTML-контент
                    if !notification.displayHTML.isEmpty {
                        HTMLTextView(htmlString: notification.displayHTML)
                            .font(.body)
                            .foregroundStyle(.primary)
                    } else if !notification.displayAnnouncement.isEmpty {
                        Text(notification.displayAnnouncement)
                            .font(.body)
                            .foregroundStyle(.primary)
                    }
                }
                .padding(20)
            }
            .navigationTitle("Уведомление")
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

// MARK: - Отображение HTML

private struct HTMLTextView: UIViewRepresentable {
    let htmlString: String
    
    func makeUIView(context: Context) -> UITextView {
        let textView = UITextView()
        textView.isEditable = false
        textView.isScrollEnabled = false
        textView.backgroundColor = .clear
        textView.textContainerInset = .zero
        textView.textContainer.lineFragmentPadding = 0
        
        if let data = htmlString.data(using: .utf8),
           let attributed = try? NSAttributedString(
               data: data,
               options: [.documentType: .html, .characterEncoding: String.Encoding.utf8.rawValue],
               documentAttributes: nil
           ) {
            textView.attributedText = attributed
        } else {
            textView.text = htmlString
        }
        
        return textView
    }
    
    func updateUIView(_ uiView: UITextView, context: Context) {}
}
