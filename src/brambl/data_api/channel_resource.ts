import type { Transport } from '@connectrpc/connect';
import { createConnectTransport } from '@connectrpc/connect-web';
import { Channel, ChannelCredentials } from '@grpc/grpc-js';

/**
 * Represents a transport resource that provides a method to establish a channel connection.
 */
interface TransportResource {
  /**
   * Establishes a channel connection to the specified address and port.
   * @param address - The address to connect to.
   * @param port - The port number to connect to.
   * @param useHttpGet - By default, all requests use POST. Set this option to true to use GET for side-effect free RPCs.
   * @returns A Promise that resolves to a Channel object representing the established connection.
   */
  transportResource(address: string, port: number, useHttpGet: boolean): Transport;
}

/**
 * Represents a transport resource that provides a method to establish a channel connection.
 *
 */
export const TransportResource: TransportResource = {
  transportResource: (address: string, port: number, secureConnection: boolean = false): Transport => {
    const transport = createConnectTransport({
      baseUrl: `${address}:${port}`,
      useBinaryFormat: secureConnection,
      // By default, all requests use POST. Set this option to true to use GET
      // for side-effect free RPCs.
      useHttpGet: false,
    });
    return transport;
  },
};

/**
 * A resource that provides a connection to a GRPC server.
 */
interface RpcChannelResource {
  /**
   * Creates a resource that provides a connection to a GRPC server.
   *
   * @param address the host address of the GRPC server.
   * @param port the port of the GRPC server.
   * @param secureConnection whether to use a secure connection.
   * @returns A Promise that resolves to a gRPC channel.
   */
  channelResource(address: string, port: number, secureConnection: boolean): Promise<Channel>;
}

/**
 * A resource that provides a connection to a GRPC server.
 * @deprecated Use TransportResource instead.
 */
export const RpcChannelResource: RpcChannelResource = {
  channelResource: (address: string, port: number, secureConnection: boolean): Promise<Channel> => {
    const channelPromise = new Promise<Channel>((resolve, reject) => {
      try {
        let channelCredentials: ChannelCredentials;
        if (secureConnection) {
          channelCredentials = ChannelCredentials.createSsl();
        } else {
          channelCredentials = ChannelCredentials.createInsecure();
        }

        const channel = new Channel(
          `${address}:${port}`,
          channelCredentials,
          undefined, // TODO figure out how grpc works with channel options
        );

        resolve(channel);
      } catch (err) {
        reject(err);
      }
    });

    return channelPromise;
  },
};
