import SwiftUI

// MARK: - Менеджер шрифтов (только системный шрифт SF Pro)
// Кастомные шрифты (Open Sans, Golos Text) удалены — оставляем только системный,
// как просил пользователь. Все методы .app/.appHeadline/.appBody теперь возвращают
// системный шрифт, чтобы не нужно было переписывать вызовы в других файлах.

enum FontMode: String, CaseIterable {
    case system = "system"  // только системный режим

    var label: String { "Системные" }
    var icon: String { "textformat" }
}

// MARK: - FontManager (заглушка, не делает ничего)
enum FontManager {
    static var currentMode: FontMode { .system }

    /// Раньше регистрировала кастомные шрифты Open Sans / Golos Text.
    /// Сейчас — no-op, оставлено для обратной совместимости с вызовами в scheduleApp.init().
    static func registerFonts() {
        // Намеренно пусто: используем только системный шрифт SF Pro.
    }
}
