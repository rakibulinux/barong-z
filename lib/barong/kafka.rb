require 'kafka'

module Stream
  class <<self
    def connection
      @connection ||= Kafka.new(ENV.fetch("KAFKA_URL", "localhost:9092").split(","))
    end

    def topics
      @topics ||= connection.topics
    end

    def create_topic(topic)
      unless topics.include?(topic)
        connection.create_topic(topic, num_partitions: 10)
        topics << topic
      end
    end

    def consumer
      connection.consumer(group_id: "zsmartex")
    end

    def producer
      connection.async_producer(
        # Trigger a delivery once 1 messages have been buffered.
        delivery_threshold: 1,
  
        # Trigger a delivery every 5 milliseconds.
        delivery_interval: 0.005,
      )
    end

    def produce(topic, key, payload={})
      create_topic(topic)
      payload = JSON.dump payload

      producer.produce(payload, key: key, topic: topic)
      producer.deliver_messages
    end

    def enqueue_event(kind, id, event, payload)
      create_topic("rango.events")

      payload = JSON.dump payload

      producer.produce(payload, key: [kind, id, event].join("."), topic: "rango.events")
      producer.deliver_messages
    end

  end
end
