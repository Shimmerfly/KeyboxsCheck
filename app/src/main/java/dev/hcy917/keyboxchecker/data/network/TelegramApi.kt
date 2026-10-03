package dev.hcy917.keyboxchecker.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit

/** A structured failure from the Bot API, so the UI can say something useful. */
class TelegramException(
    message: String,
    val errorCode: Int? = null,
    val retryAfterSeconds: Int? = null,
) : IOException(message)

/** One `.xml` document discovered in the configured channel. */
data class TelegramDocument(
    val fileName: String,
    val fileId: String,
    val fileUniqueId: String,
    val fileSize: Long,
    val messageId: Long,
    val dateSeconds: Long,
)

/**
 * The documents found in one poll, plus the offset the next poll should start
 * from so the same message is never ingested twice.
 */
data class TelegramBatch(val documents: List<TelegramDocument>, val nextOffset: Long?)

/**
 * Minimal Telegram Bot API client.
 *
 * Only `getUpdates` and file download are used: a bot cannot search a channel,
 * so the app walks the recent updates of a channel the bot is a member of.
 * That limitation is surfaced in the UI instead of being hidden here.
 */
class TelegramApi(
    private val client: OkHttpClient,
    private val botToken: String,
    private val maxFileBytes: Long = DEFAULT_MAX_FILE_BYTES,
) {

    private val trimmedToken = botToken.trim()

    /** Polls recent updates and keeps only `.xml` documents from [targetChannel]. */
    suspend fun pollChannel(
        targetChannel: String,
        offset: Long?,
        limit: Int = 100,
    ): TelegramBatch = withContext(Dispatchers.IO) {
        val payload = apiCall(
            method = "getUpdates",
            form = FormBody.Builder()
                .add("limit", limit.coerceIn(1, 100).toString())
                .add("timeout", "0")
                .add("allowed_updates", """["channel_post","message"]""")
                .apply { if (offset != null && offset > 0) add("offset", offset.toString()) }
                .build(),
        )

        val updates = payload.optJSONArray("result")
            ?: throw TelegramException("Telegram 响应缺少 result 字段")

        val documents = ArrayList<TelegramDocument>()
        var highestUpdateId = -1L

        for (index in 0 until updates.length()) {
            val update = updates.optJSONObject(index) ?: continue
            val updateId = update.optLong("update_id", -1L)
            if (updateId > highestUpdateId) highestUpdateId = updateId

            val message = update.optJSONObject("channel_post")
                ?: update.optJSONObject("message")
                ?: update.optJSONObject("edited_channel_post")
                ?: continue

            val chat = message.optJSONObject("chat") ?: continue
            val chatId = chat.optLong("id", Long.MIN_VALUE).takeIf { it != Long.MIN_VALUE }
            val username = chat.optStringOrNull("username")
            if (!matchesChannel(chatId, username, targetChannel)) continue

            val document = message.optJSONObject("document") ?: continue
            val fileName = document.optStringOrNull("file_name") ?: continue
            if (!isKeyboxFileName(fileName)) continue

            val fileId = document.optStringOrNull("file_id") ?: continue
            documents += TelegramDocument(
                fileName = fileName,
                fileId = fileId,
                fileUniqueId = document.optStringOrNull("file_unique_id") ?: fileId,
                fileSize = document.optLong("file_size", -1L),
                messageId = message.optLong("message_id", -1L),
                dateSeconds = message.optLong("date", -1L),
            )
        }

        TelegramBatch(
            documents = documents,
            nextOffset = if (highestUpdateId >= 0) highestUpdateId + 1 else null,
        )
    }

    /** Resolves the temporary download path and fetches the document bytes. */
    suspend fun downloadDocument(document: TelegramDocument): ByteArray = withContext(Dispatchers.IO) {
        if (document.fileSize > maxFileBytes) {
            throw TelegramException("${document.fileName} 超过 ${maxFileBytes / 1024 / 1024}MB，已跳过")
        }
        val payload = apiCall(
            method = "getFile",
            form = FormBody.Builder().add("file_id", document.fileId).build(),
        )
        val filePath = payload.optJSONObject("result")?.optStringOrNull("file_path")
            ?: throw TelegramException("Telegram 未返回 ${document.fileName} 的下载路径")

        val request = Request.Builder()
            .url("https://api.telegram.org/file/bot$trimmedToken/$filePath")
            .get()
            .build()

        client.newBuilder()
            .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build()
            .newCall(request)
            .execute()
            .use { response ->
                if (!response.isSuccessful) {
                    throw TelegramException("下载 ${document.fileName} 失败：HTTP ${response.code}", response.code)
                }
                val declared = response.body.contentLength()
                if (declared > maxFileBytes) {
                    throw TelegramException("${document.fileName} 超过 ${maxFileBytes / 1024 / 1024}MB，已跳过")
                }
                val bytes = response.body.bytes()
                if (bytes.size.toLong() > maxFileBytes) {
                    throw TelegramException("${document.fileName} 超过 ${maxFileBytes / 1024 / 1024}MB，已跳过")
                }
                bytes
            }
    }

    // ---------------------------------------------------------------- plumbing

    private suspend fun apiCall(method: String, form: FormBody): JSONObject {
        if (trimmedToken.isEmpty()) throw TelegramException("尚未填写 Telegram Bot Token")
        val request = Request.Builder()
            .url("https://api.telegram.org/bot$trimmedToken/$method")
            .post(form)
            .build()

        var retried = false
        while (true) {
            val response = runCatching {
                client.newBuilder()
                    .callTimeout(CALL_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .build()
                    .newCall(request)
                    .execute()
            }.getOrElse {
                throw TelegramException("无法连接 Telegram：${it.message ?: it::class.java.simpleName}")
            }

            val payload = response.use { reply ->
                val body = reply.body.string()
                val root = runCatching { JSONObject(body) }.getOrNull()
                    ?: throw TelegramException("Telegram 返回了无法解析的响应（HTTP ${reply.code}）", reply.code)

                if (root.optBoolean("ok")) {
                    root
                } else {
                    val description = root.optStringOrNull("description") ?: "Telegram 拒绝了该请求"
                    val errorCode = root.optInt("error_code", 0).takeIf { it != 0 } ?: reply.code
                    val retryAfter = root.optJSONObject("parameters")
                        ?.optInt("retry_after", 0)
                        ?.takeIf { it > 0 }

                    if (retryAfter != null && !retried) {
                        // Rate limited: honour the server's cooldown exactly once.
                        retried = true
                        delay(retryAfter * 1000L)
                        null
                    } else {
                        throw TelegramException(description, errorCode, retryAfter)
                    }
                }
            }
            if (payload != null) return payload
        }
    }

    companion object {

        const val DEFAULT_MAX_FILE_BYTES: Long = 8L * 1024L * 1024L
        private const val CALL_TIMEOUT_SECONDS = 30L

        /**
         * Accepts `@name`, `name`, `https://t.me/name` and the numeric channel id
         * in both the full `-100…` form and the bare form Telegram shows in links.
         */
        fun matchesChannel(chatId: Long?, username: String?, target: String): Boolean {
            val cleaned = normalizeChannel(target) ?: return false
            if (!username.isNullOrBlank() && username.equals(cleaned, ignoreCase = true)) return true
            val id = chatId ?: return false
            if (cleaned == id.toString()) return true
            val numeric = cleaned.toLongOrNull() ?: return false
            if (numeric == id) return true
            // Channels are published as -100<bare id>; users paste either half.
            if (numeric > 0 && id == SUPERGROUP_PREFIX - numeric) return true
            if (id > 0 && cleaned == (SUPERGROUP_PREFIX - id).toString()) return true
            return false
        }

        fun normalizeChannel(target: String): String? = target.trim()
            .removePrefix("https://t.me/")
            .removePrefix("http://t.me/")
            .removePrefix("t.me/")
            .removePrefix("@")
            .trim()
            .takeIf { it.isNotEmpty() }

        fun isKeyboxFileName(name: String): Boolean = name.endsWith(".xml", ignoreCase = true)

        private const val SUPERGROUP_PREFIX = -1_000_000_000_000L
    }
}

/** `optString` turns a JSON null into the literal "null"; this keeps it honest. */
private fun JSONObject.optStringOrNull(key: String): String? =
    if (!has(key) || isNull(key)) null else optString(key).trim().takeIf { it.isNotEmpty() }
