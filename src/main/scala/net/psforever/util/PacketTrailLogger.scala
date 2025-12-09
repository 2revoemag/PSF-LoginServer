// Copyright (c) 2025 PSForever
package net.psforever.util

import io.circe.generic.auto._
import io.circe.syntax._
import java.io.{File, PrintWriter}
import java.time.Instant
import net.psforever.packet.PlanetSidePacket
import org.log4s.getLogger

import scala.collection.mutable

/**
 * Data structure representing a single packet sent to the client.
 */
case class PacketRecord(
  timestamp: Long,        // ms since session start
  packetType: String,     // class name (e.g., "ObjectCreateMessage")
  packetSize: Int,        // serialized byte count (estimated)
  sequenceNum: Int,       // protocol sequence number (0 for now - not tracked)
  summary: String         // key fields, truncated to ~100 chars
)

/**
 * Data structure for the complete dump on disconnect.
 */
case class DisconnectDump(
  sessionId: String,
  playerName: Option[String],
  accountName: Option[String],
  zone: Option[String],
  position: Option[(Float, Float, Float)],
  lastKnownState: String,       // alive, dead, in_vehicle, etc.
  sessionDuration: Long,        // ms
  totalPacketsSent: Int,
  disconnectType: String,       // keepalive_timeout, error, unknown
  disconnectTime: String,       // ISO-8601 timestamp
  packets: List[PacketRecord]
)

/**
 * Ring buffer for tracking packet history per session.
 * Thread-safe circular buffer that automatically overwrites oldest entries.
 */
class PacketTrailRingBuffer(maxSize: Int = 6000) {
  private val buffer = new mutable.ArrayBuffer[PacketRecord](maxSize)
  private var writeIndex = 0
  private var isFull = false

  /**
   * Add a packet to the buffer. Thread-safe.
   */
  def add(record: PacketRecord): Unit = synchronized {
    if (buffer.size < maxSize) {
      buffer += record
    } else {
      buffer(writeIndex) = record
      isFull = true
    }
    writeIndex = (writeIndex + 1) % maxSize
  }

  /**
   * Get all packets in chronological order (oldest first).
   */
  def getAll: List[PacketRecord] = synchronized {
    if (!isFull) {
      buffer.toList
    } else {
      // If full, oldest is at writeIndex, need to reorder
      (buffer.drop(writeIndex) ++ buffer.take(writeIndex)).toList
    }
  }

  /**
   * Get the total number of packets recorded (including overwritten ones).
   */
  def totalCount: Int = synchronized {
    if (isFull) writeIndex + maxSize * ((writeIndex + maxSize - 1) / maxSize)
    else buffer.size
  }

  /**
   * Clear the buffer.
   */
  def clear(): Unit = synchronized {
    buffer.clear()
    writeIndex = 0
    isFull = false
  }
}

/**
 * Main logger for packet trail recording and dumping.
 */
object PacketTrailLogger {
  private val log = getLogger

  // Configuration (will be loaded from application.conf)
  private var enabled = Config.app.packetTrailLogger.enabled
  private val bufferSize = Config.app.packetTrailLogger.bufferSize
  private val outputDirectory = Config.app.packetTrailLogger.outputDirectory

  /**
   * Create a packet summary string from a PlanetSidePacket.
   * Extracts key fields and truncates to ~100 chars.
   */
  def createPacketSummary(packet: PlanetSidePacket): String = {
    val summary = packet.toString
    if (summary.length > 100) {
      summary.take(97) + "..."
    } else {
      summary
    }
  }

  /**
   * Record a packet being sent.
   */
  def recordPacket(
    buffer: PacketTrailRingBuffer,
    sessionStartTime: Long,
    packet: PlanetSidePacket
  ): Unit = {
    if (!enabled) return

    try {
      val timestamp = System.currentTimeMillis() - sessionStartTime
      val record = PacketRecord(
        timestamp = timestamp,
        packetType = packet.getClass.getSimpleName,
        packetSize = estimatePacketSize(packet),
        sequenceNum = 0, // Not tracked currently
        summary = createPacketSummary(packet)
      )
      buffer.add(record)
    } catch {
      case ex: Exception =>
        log.error(ex)(s"Failed to record packet: ${packet.getClass.getSimpleName}")
    }
  }

  /**
   * Estimate packet size (rough approximation).
   * In the future, this could be replaced with actual serialized size.
   */
  private def estimatePacketSize(packet: PlanetSidePacket): Int = {
    // Rough estimate: use toString length as proxy
    // Better approach would be to serialize and measure, but that's expensive
    packet.toString.length
  }

  /**
   * Dump packet buffer to JSON file on unexpected disconnect.
   */
  def dumpOnDisconnect(
    buffer: PacketTrailRingBuffer,
    sessionStartTime: Long,
    sessionId: String,
    playerName: Option[String],
    accountName: Option[String],
    zone: Option[String],
    position: Option[(Float, Float, Float)],
    lastKnownState: String,
    disconnectType: String
  ): Unit = {
    if (!enabled) return

    try {
      val sessionDuration = System.currentTimeMillis() - sessionStartTime
      val packets = buffer.getAll
      val totalPackets = buffer.totalCount

      val dump = DisconnectDump(
        sessionId = sessionId,
        playerName = playerName,
        accountName = accountName,
        zone = zone,
        position = position,
        lastKnownState = lastKnownState,
        sessionDuration = sessionDuration,
        totalPacketsSent = totalPackets,
        disconnectType = disconnectType,
        disconnectTime = Instant.now().toString,
        packets = packets
      )

      // Ensure output directory exists
      val outDir = new File(outputDirectory)
      if (!outDir.exists()) {
        outDir.mkdirs()
      }

      // Create filename
      val playerNameStr = playerName.getOrElse("unknown")
      val timestamp = Instant.now().toString.replace(":", "-")
      val filename = s"packet_dump_${playerNameStr}_${timestamp}.json"
      val filepath = new File(outDir, filename)

      // Write JSON
      val json = dump.asJson.spaces2
      val writer = new PrintWriter(filepath)
      try {
        writer.write(json)
        log.info(s"Packet trail dump written to: ${filepath.getAbsolutePath}")
        log.info(s"  Session duration: ${sessionDuration}ms")
        log.info(s"  Total packets sent: $totalPackets")
        log.info(s"  Packets in buffer: ${packets.size}")
      } finally {
        writer.close()
      }
    } catch {
      case ex: Exception =>
        log.error(ex)(s"Failed to dump packet trail for session $sessionId")
    }
  }

  /**
   * Create a new ring buffer for a session.
   */
  def createBuffer(): PacketTrailRingBuffer = {
    if (enabled) {
      new PacketTrailRingBuffer(bufferSize)
    } else {
      // If disabled, return a dummy buffer that does nothing
      new PacketTrailRingBuffer(0)
    }
  }

  /**
   * Check if packet trail logging is enabled.
   */
  def isEnabled: Boolean = enabled
}
