.. _ble_mesh_demo:

Bluetooth: Mesh Demo
####################

Overview
********

This sample is a Bluetooth Mesh application intended for demonstration
purposes only. The application provisions and configures itself (i.e. no
external provisioner needed) with hard-coded network and application key
values. The local unicast address can be set using a NODE_ADDR build
variable (e.g. NODE_ADDR=0x0001 for unicast address 0x0001), or by
manually editing the value in the ``board.h`` file.

Because of the hard-coded values, the application is not suitable for
production use, but is quite convenient for quick demonstrations of mesh
functionality.

The application has some features especially designed for the BBC
micro:bit boards, such as the ability to send messages using the board's
buttons as well as showing information of received messages on the
board's 5x5 LED display. It's generally recommended to use unicast
addresses in the range of 0x0001-0x0009 for the micro:bit since these
map nicely to displayed addresses and the list of destination addresses
which can be cycled with a button press.

A special address, 0x000f, will make the application become a heart-beat
publisher and enable the other nodes to show information of the received
heartbeat messages.

Requirements
************

* A board with Bluetooth LE support, or
* QEMU with BlueZ running on the host

Building and Running
********************

This sample can be found under :zephyr_file:`samples/bluetooth/mesh_demo` in
the Zephyr tree.

See :ref:`bluetooth samples section <bluetooth-samples>` for details on how
to run the sample inside QEMU.

For other boards, build and flash the application as follows:

.. zephyr-app-commands::
   :zephyr-app: samples/bluetooth/mesh_demo
   :board: <board>
   :goals: flash
   :compact:

Refer to your :ref:`board's documentation <boards>` for alternative
flash instructions if your board doesn't support the ``flash`` target.

Additional kconfig options need to be set on the Bluetooth controller
application if it runs on a separate board or SoC core. Build the controller
application (i.e. ``hci_xx`` sample of your choosing) with the
:zephyr_file:`samples/bluetooth/hci_spi/mesh.conf` as the extra configuration.

For the :ref:`nrf5340dk_nrf5340` specifically, build and flash the
:ref:`bluetooth-hci-ipc-sample` application with this configuration
:zephyr_file:`samples/bluetooth/hci_ipc/nrf5340_cpunet_bt_mesh-bt_ll_sw_split.conf`
to enable mesh support.

Please note, the number of extended advertiser instances should be set the same
on both configurations as in the Bluetooth Mesh sample as well as the controller sample.
